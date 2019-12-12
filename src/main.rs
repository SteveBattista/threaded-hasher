#![forbid(unsafe_code)]
use clap::{App, Arg};
use data_encoding::HEXUPPER;
use ring::digest::{Context, SHA256, SHA384, SHA512,Algorithm,Digest};
use scoped_threadpool::Pool;
use std::error::Error;
use std::fs;
use std::io::{BufReader, Read};
use std::process::exit;

fn main() {
    let matches = App::new("Threaded Hasher")
                          .version("1.0")
                          .author("Stephen Battista <stephen.battista@gmail.com>")
                          .about("Implements hashing with a configurable thread pool")
                          .arg(Arg::with_name("algo")
                               .short("a")
                               .long("algorithm")
                               .value_name("256 | 384 | 512")
                               .help("Chooses what algorthim to use SHA256->(256), SHA384->(384) or SHA512->(512). Default is SHA256.")
                               .takes_value(true))
                          .arg(Arg::with_name("pool")
			        .short("p")
                               .long("pool")
                               .value_name("#")
                               .help("Sets the size of the pool of maximum number of concurrent threads when hashing. Default is 10. Large numbers (> 60) may cause the progam not to hash all files.")
                               .takes_value(true))
                          .arg(Arg::with_name("files")
                               .value_name("files")
                               .help("Place one or more files to hash. Those that can not be found will be ommited from the results. Directories will be ommitted. Links will be treated like normal files.")
                               .required(true).min_values(1))
                          .get_matches();

    let hashalgo: &Algorithm;
    let inputhash = matches.value_of("algo").unwrap_or("256");
    match inputhash {
        "256" => hashalgo = &SHA256,
        "384" => hashalgo = &SHA384,
        "512" => hashalgo = &SHA512,
        _ => {
            println!("Please choose 256, 384 or 512 for type of SHA hash.");
            exit(0);
        }
    }
    //  println!("Hash chosen is {}", inputhash);

    let inputpool = matches.value_of("pool").unwrap_or("10");
    let poolresult = inputpool.parse();
    let poolnumber;
    match poolresult {
        Ok(n) => poolnumber = n,
        Err(_e) => {
            println!("Please choose a number for the number of threads.");
            exit(0);
        }
    }
    let mut pool = Pool::new(poolnumber);
    //    println!("pool chosen is {}", inputpool);

    let inputfiles: Vec<_> = matches.values_of("files").unwrap().collect();
    //   println!("Files chosen is {}", inputpool.len());

    pool.scoped(|scoped| {
        for file in inputfiles {
            scoped.execute(move || {
                let _x = gethashofile(&file, hashalgo);
            });
        }
    });
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
    println!("{} : {} : {}", path, metadata.len(), HEXUPPER.encode(digest.as_ref()));
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
        assert_eq!(test::from_hex(acutal).unwrap(),acutal_binary);
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
