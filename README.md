# CKRS - Cryptoki Key Retention Service

Use the Linux Kernel's Key Retention Service as a "virtual cryptographic hardware" through the PKCS #11 v3.10 spec. Replacement for the `ssh-agent(1)`.

## Documentation:

TODO:

## Usage

TODO:

```bash
shh -I path/to/libcryptokikrs.so user@domain
```

## Building

To build the project just run `zig build`, if you want to test things run `zig build test`. To test with ssh use the Makefile under `test/`, to do so:
* `make docker`: Will generate a new ssh ca user certificate and generate and sign a user certificate (under `test/user/`), it also start a docker with ssh on port 2222.
* `make ssh`: Will attempt to connect to the server on port 2222 using `libcryptokikrs`.
