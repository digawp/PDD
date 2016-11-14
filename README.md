# Privacy-preserving Data Deduplication (PDD)

This is an implementation of a soon-to-be-submitted-paper for conference in April 2017 (deadline of submission in November 2016).

Currently the repo only consist of the C.

## Requirements

- [Crypto++](https://www.cryptopp.com/) 5.6.5
- [Intel SGX](https://github.com/01org/linux-sgx/)

## Build and Run

### P aka Proxy

None yet.

### C aka Client

Currently C can only hash a file and carry out blind signature protocol by itself.

Don't forget to run the proxy first before running the client (when the proxy has been implemented, that is).

    make ClientApp
    ./ClientApp

## Credits

- @digawp (implementation)
- Hung (design)
