#![forbid(unsafe_code)]
use clap::{App, Arg};
use data_encoding::HEXUPPER;
use indicatif::MultiProgress;
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use ring::digest::{Algorithm, Context, Digest, SHA256, SHA384, SHA512};
use scoped_threadpool::Pool;
use std::error::Error;
use std::fs;
use std::io::{BufReader, Read};
use std::process::exit;
//use std::sync::Arc;
use std::time::Duration;
use std::time::UNIX_EPOCH;
use walkdir::WalkDir;
const FILENAME_LEN: usize = 120;

fn main() {
    let matches = App::new("Threaded Hasher")
                            .version("1.0")
                            .author("Stephen Battista <stephen.battista@gmail.com>")
                            .about("Implements hashing with a configurable thread pool")
                            .arg(Arg::with_name("algo")
                               .short("a")
                               .long("algorithm")
                               .value_name("256 | 384 | 512")
                               .help("Chooses what algorthim to use SHA256->(256), SHA384->(384) or SHA512->(512). Default is SHA512.")
                               .takes_value(true))
                            .arg(Arg::with_name("verbose")
                               .short("v")
                              .long("verbose")
                              .help("Shows the names of the files being hashed.")
                              .takes_value(false))
                            .arg(Arg::with_name("pool")
			                    .short("p")
                               .long("pool")
                               .value_name("#")
                               .help("Sets the size of the pool of maximum number of concurrent threads when hashing. Default is number of CPUs. Large numbers (> 60) may cause the progam not to hash all files.")
                               .takes_value(true))
                            .arg(Arg::with_name("directory")
                               .short("d")
                               .long("directory")
                               .value_name("DIRECTORY")
                               .help("Directory to start hashing. Default is current working directory. Program does not follow symbolic links.")
                               .takes_value(true))
                            .get_matches();

    let inputhash = matches.value_of("algo").unwrap_or("512");
    let verbose = matches.is_present("verbose");
    let hashalgo: &Algorithm = match inputhash {
        "256" => &SHA256,
        "384" => &SHA384,
        "512" => &SHA512,
        _ => {
            println!("Please choose 256, 384 or 512 for type of SHA hash.");
            exit(0);
        }
    };
    //  println!("Hash chosen is {}", inputhash);
    let binding = num_cpus::get().to_string();
    let inputpool = matches.value_of("pool").unwrap_or(&binding);
    let poolresult = &inputpool.parse();
    let poolnumber = match poolresult {
        Ok(n) => n,
        Err(_e) => {
            println!("Please choose a number for the number of threads.");
            exit(0);
        }
    };
    let mut pool = Pool::new(*poolnumber);
    // println!("pool chosen is {}", inputpool);
    // println!("Files chosen is {}", inputpool.len());

    let input_directoy = matches.value_of("directory").unwrap_or(".");

    let mut inputfiles: Vec<String> = Vec::new();
    let spinner = ProgressBar::new_spinner();
    spinner.set_prefix("Constucting file list:");
    spinner.set_style(
        ProgressStyle::default_bar()
            .template("{prefix} [{elapsed_precise}] {spinner:.yellow/cyan}")
            .expect("Style is wrong."),
    );
    for entry in WalkDir::new(input_directoy) {
        inputfiles.push(entry.unwrap().path().display().to_string());

        spinner.tick();
    }

    spinner.finish();
    let m = MultiProgress::new();
    let bar = ProgressBar::new(inputfiles.len() as u64);
    let pb = m.add(bar);

    //pb.set_style(sty.clone());
    pool.scoped(|scoped| {
        for mut file in inputfiles {
            let pb_clone = pb.clone();
            let m = m.clone();
            scoped.execute(move || {
                if verbose {
                    if file.len() > FILENAME_LEN {
                        let split_pos = file.char_indices().nth_back(FILENAME_LEN).unwrap().0;
                        file = file[split_pos..].to_string();
                    }
                    let spinner = m.add(ProgressBar::new_spinner().with_message(file.clone()));
                    spinner.enable_steady_tick(Duration::from_millis(100));
                    let _x = gethashofile(&file, hashalgo);
                    pb_clone.inc(1);
                    spinner.finish_and_clear();
                } else {
                    let _x = gethashofile(&file, hashalgo);
                    pb_clone.inc(1);
                }
            });
        }
    });
    spinner.finish_and_clear();
}

fn var_digest<R: Read>(
    mut reader: R,
    hashalgo: &'static Algorithm,
) -> Result<Digest, Box<dyn Error>> {
    let mut context = Context::new(hashalgo);
    let mut buffer = [0; 1024];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }
    Ok(context.finish())
}

fn gethashofile(path: &str, hashalgo: &'static Algorithm) -> Result<(), Box<dyn Error>> {
    let metadata = fs::metadata(path)?;
    let input = fs::File::open(path)?;
    let reader = BufReader::new(input);
    let digest = var_digest(reader, hashalgo)?;
    println!(
        "{} : {} : {} : {}",
        path,
        metadata.len(),
        metadata
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        HEXUPPER.encode(digest.as_ref())
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use ring::test;

    #[test]
    fn test_encode_decode() {
        let deadbeef = vec![0xde, 0xad, 0xbe, 0xef];
        assert_eq!(HEXUPPER.decode(b"DEADBEEF").unwrap(), deadbeef);
        assert_eq!(HEXUPPER.encode(&deadbeef), "DEADBEEF");
    }

    #[test]
    fn test_from_hex() {
        let acutal = "DEADBEEF";
        let acutal_binary = HEXUPPER.decode(b"DEADBEEF").unwrap();
        assert_eq!(test::from_hex(acutal).unwrap(), acutal_binary);
    }

    #[test]
    fn test_256_1() {
        let mut context = Context::new(&SHA256);
        context.update(b"abc");
        let actual = context.finish();
        let expected_hex = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
        let expected: Vec<u8> = test::from_hex(expected_hex).unwrap();
        assert_eq!(&expected, &actual.as_ref());
    }

    #[test]
    fn test_256_2() {
        let mut context = Context::new(&SHA256);
        context.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let actual = context.finish();
        let expected_hex = "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1";
        let expected: Vec<u8> = test::from_hex(expected_hex).unwrap();
        assert_eq!(&expected, &actual.as_ref());
    }

    #[test]
    fn test_384_1() {
        let mut context = Context::new(&SHA384);
        context.update(b"abc");
        let actual = context.finish();
        let expected_hex = "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7";
        let expected: Vec<u8> = test::from_hex(expected_hex).unwrap();
        assert_eq!(&expected, &actual.as_ref());
    }

    #[test]
    fn test_384_2() {
        let mut context = Context::new(&SHA384);
        context.update(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        let actual = context.finish();
        let expected_hex = "09330C33F71147E83D192FC782CD1B4753111B173B3B05D22FA08086E3B0F712FCC7C71A557E2DB966C3E9FA91746039";
        let expected: Vec<u8> = test::from_hex(expected_hex).unwrap();
        assert_eq!(&expected, &actual.as_ref());
    }

    #[test]
    fn test_512_1() {
        let mut context = Context::new(&SHA512);
        context.update(b"abc");
        let actual = context.finish();
        let expected_hex = "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F";
        let expected: Vec<u8> = test::from_hex(expected_hex).unwrap();
        assert_eq!(&expected, &actual.as_ref());
    }

    #[test]
    fn test_512_2() {
        let mut context = Context::new(&SHA512);
        context.update(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        let actual = context.finish();
        let expected_hex = "8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909";
        let expected: Vec<u8> = test::from_hex(expected_hex).unwrap();
        assert_eq!(&expected, &actual.as_ref());
    }
}
