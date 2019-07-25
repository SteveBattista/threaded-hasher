Threaded Hasher 1.0
Implements hashing with a configurable thread pool

USAGE:
    threaded-hasher [OPTIONS] <files>...

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -a, --algorithm <256 | 384 | 512>    Chooses what algorthim to use SHA256->(256), SHA384->(384) or SHA512->(512),
                                         Default is SHA256.
    -p, --pool <#>                       Sets the size of the pool of maximum number of concurrent threads when hashing.
                                         Default is 10. Large numbers (> 60) may cause the progam not to hash all files.

ARGS:
    <files>...    Place one or more files to hash. Those that can not be found will be ommited from the results.
                  Directories will be ommitted. Links will be treated like normal files.
