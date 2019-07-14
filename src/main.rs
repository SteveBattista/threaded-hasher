
use std::env;
use ring::digest::{Context, Digest, SHA512};
use std::fs::File;
use std::io::{BufReader, Read};
use data_encoding::HEXUPPER;
use std::error::Error;
use scoped_threadpool::Pool;

fn main() {
   let mut args: Vec<String> = env::args().collect();
   args.remove(0);
   let mut pool = Pool::new(20); 
   pool.scoped(|scoped| {
      for file in args {
            scoped.execute( move || {
              let _x = gethashofile(&file);
            });
      }
    });
  
}

fn sha512_digest<R: Read>(mut reader: R) -> Result< Digest, Box<dyn Error>>  {
    let mut context = Context::new(&SHA512);
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

fn gethashofile(path : &str) -> Result<(), Box<dyn Error>> {
   let input = File::open(path)?;
   let reader = BufReader::new(input);
   let digest = sha512_digest(reader)?; 
   println!("{} SHA-512 digest is {}", path, HEXUPPER.encode(digest.as_ref()));
   Ok(())
}
