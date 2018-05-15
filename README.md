# signnode-php
This repository contains PHP source codes, which allow to generate Metahash address, send transaction and verify data signature.

## Install from source

### Get the source code

Clone the repository by:
```shell
git clone https://github.com/metahashorg/signnode-php
```

### Install
For using on server/local machine, you need to configure the service as follows: replace the content of the file `/includes/config.php.tmp` with the correct one and remove `.tmp` extension.

## Available service methods

- `mhc_verify` (transaction data signature verification)

- `mh_sendTransaction` (sending a transaction)

- `mh_createAddress` (generating a key)
