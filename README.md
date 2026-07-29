# fernet

An R implementation of the [Fernet](https://github.com/fernet/spec) symmetric
encryption scheme. Fernet combines AES-CBC encryption with HMAC-SHA256
authentication, producing URL-safe base64 tokens that are easy to store and
transmit.

## Features

- Generate random 256-bit keys
- Encrypt plaintext into authenticated, tamper-evident tokens
- Decrypt tokens with HMAC verification and optional time-to-live (TTL) checks

## Installation

```r
# install.packages("remotes")
remotes::install_github("<your-username>/fernet")
```

## Usage

```r
library(fernet)

# Generate a key and keep it secret; anyone with this key can
# decrypt your tokens.
key <- generate_key()

# Encrypt a message
token <- encrypt(key, "hello world")
token
#> [1] "gAAAAABk..."

# Decrypt it
decrypt(key, token)
#> [1] "hello world"
```

### Token expiration

`decrypt()` accepts an optional `ttl` (in seconds). If the token's embedded
timestamp is older than `ttl` seconds, decryption fails:

```r
token <- encrypt(key, "hello world")

# Succeeds: token is fresh
decrypt(key, token, ttl = 60)

# Fails once more than 60 seconds have elapsed since encryption
Sys.sleep(61)
decrypt(key, token, ttl = 60)
#> Error: The token has expired
```

## fernet spec

A Fernet token has the following structure:

| Field      | Size     | Description                                   |
|------------|----------|------------------------------------------------|
| Version    | 1 byte   | Always `0x80`                                   |
| Timestamp  | 8 bytes  | Big-endian Unix timestamp at encryption time     |
| IV         | 16 bytes | Random AES initialization vector                |
| Ciphertext | variable | AES-128-CBC encrypted data, PKCS7-padded         |
| HMAC       | 32 bytes | HMAC-SHA256 over the fields above                |

These bytes are concatenated and encoded as URL-safe base64 (`-`/`_` instead
of `+`/`/`) to produce the final token.

The 256-bit key passed to `encrypt()`/`decrypt()` is split into two 128-bit
halves: the first half signs the token (HMAC), and the second half encrypts
the payload (AES-CBC).

On decryption, the version byte, token length, and HMAC are all validated
before the ciphertext is decrypted, so tampered or corrupted tokens are
rejected with an error rather than silently producing garbage output.

for more information please check out: [Fernet repo](https://github.com/fernet/spec/blob/master/Spec.md)