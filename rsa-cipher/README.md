Install OpenSSL to generate RSA key pairs

```sh
openssl req -x509 -newkey rsa:keySize -keyout privateFilename.pem -out publicFilename.pem -config openssl.cnf
```