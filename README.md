[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

<h1>Threaded Hasher 1.0 <br></h1>
Implements hashing with a configurable thread pool<br>

<h2>USAGE:<br></h2>

<h3>FLAGS:<br></h3>
    -h, --help       Prints help information<br>
    -V, --version    Prints version information<br>

<h3>OPTIONS:<br></h3>
    -a, --algorithm <256 | 384 | 512>    Chooses what algorthim to use SHA256->(256), SHA384->(384) or SHA512->(512),
                                         Default is SHA256. <br> <br>
    -p, --pool <#>                       Sets the size of the pool of maximum number of concurrent threads when hashing.<br>
                                         Default is 10. Large numbers (> 60) may cause the progam not to hash all files.<br>

<h3>ARGS:<br></h3>
    <files>...    Place one or more files to hash. Those that can not be found will be ommited from the results.<br>
                  Directories will be ommitted. Links will be treated like normal files.<br>
