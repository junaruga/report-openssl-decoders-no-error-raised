# report-openssl-fips-decoders-no-error-raised

How to use

Edit `OPENSSL_DIR` for your OpenSSL in `Makefile`.

Edit the `fipsmodule.cnf` file path in the `openssl_fips.cnf`. Set the file to the `$(OPENSSL_DIR)/ssl/openssl_fips.cnf`.

Compile.

```
$ make
```

Run in both non-FIPS and FIPS cases.

```
$ make run-non-fips >& non-fips.log

$ make run-fips >& fips.log
```
