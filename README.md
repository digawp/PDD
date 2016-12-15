# Privacy-preserving Data Deduplication (PDD)

This is an implementation of a soon-to-be-submitted-paper for conference in April 2017 (deadline of submission in November 2016).

P and S currently assumes distinct file names from all Cs for simplicity.

## Requirements

- [Crypto++](https://www.cryptopp.com/) 5.6.5
- [Intel SGX](https://github.com/01org/linux-sgx/)

## Build and Run

### Server

No Server yet.

### Proxy

Make sure you have Intel SGX-capable hardware and it is enabled on BIOS (disabled by default). Also, ensure you are running from inside the `Proxy` directory.

    make run SGX_MODE=HW SGX_DEBUG=1

Or you can use `SGX_PRERELEASE=1` instead of `SGX_DEBUG=1` to make it not too verbose.

Omit `run` if you just want to compile without running it.

### Client

Don't forget to run the proxy first before running the client. Also, ensure you are running from inside the `Client` directory.

    make ClientApp && ./ClientApp [<file-name-to-upload>]

If optional arg is left out, it will default to `sample/1`

## Credits

- @digawp (implementation)
- Hung (design)
