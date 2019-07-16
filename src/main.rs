use clap::{App, Arg};
use data_encoding::HEXUPPER;
use ring::digest::{Algorithm, Context, Digest, SHA256, SHA512};
use scoped_threadpool::Pool;
use std::error::Error;
use std::fs::File;
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
                               .value_name("256 | 512")
                               .help("Chooses what algorthim to use SHA256->(256) or SHA512->(512), Default is SHA256.")
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
    match inputhash.as_ref() {
        "256" => hashalgo = &SHA256,
        "512" => hashalgo = &SHA512,
        _ => {
            println!("Please choose 256 or 512 for type of SHA hash.");
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
    let input = File::open(path)?;
    let reader = BufReader::new(input);
    let digest = var_digest(reader, hashalgo)?;
    println!("{} : {}", path, HEXUPPER.encode(digest.as_ref()));
    Ok(())
}
