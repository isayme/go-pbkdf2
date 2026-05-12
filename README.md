# go-pbkdf2

[![Go Doc](https://godoc.org/github.com/isayme/go-pbkdf2?status.svg)](https://pkg.go.dev/github.com/isayme/go-pbkdf2)
[![Coverage Status](https://coveralls.io/repos/github/isayme/go-pbkdf2/badge.svg?branch=master)](https://coveralls.io/github/isayme/go-pbkdf2?branch=master)

PBKDF2 password hashing and verification for Go.

## Install

```bash
go get github.com/isayme/go-pbkdf2
```

## Usage

### Hash a password

```go
hashed, err := pbkdf2.Hash("your plain password", pbkdf2.DefaultParams)
if err != nil {
    log.Fatal(err)
}
```

### Verify a password

```go
ok, err := pbkdf2.Verify("your plain password", hashed)
if err != nil {
    log.Fatal(err)
}
if !ok {
    log.Fatal("invalid password")
}
```

### Custom params

```go
params := pbkdf2.Params{
    Iterations: 100000,
    KeyLen:     32,
    Digest:     "sha256",
}

hashed, err := pbkdf2.Hash("password", params)
```

## Hash format

```
$pbkdf2-<digest>$i=<iterations>$<salt>$<key>
```

| Field      | Description                      |
|------------|----------------------------------|
| digest     | Hash function (sha256, sha512)  |
| iterations | Number of iterations             |
| salt       | Random salt (base64 encoded)    |
| key        | Derived key (base64 encoded)    |

## Test

```bash
go test -v ./...
```
