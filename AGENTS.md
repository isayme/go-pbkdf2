# Agents Documentation

## Project Overview

go-pbkdf2 是一个轻量级的 PBKDF2 密码哈希和校验库，基于 golang.org/x/crypto/pbkdf2 实现。

## Core Components

### pbkdf2.go

- `Params` 结构体：定义 PBKDF2 参数 (Iterations, KeyLen, SaltLen, Digest)
- `DefaultParams`：默认参数 (Iterations=100000, KeyLen=32, SaltLen=16, Digest=sha256)
- `Hash(password, params)`：生成密码哈希，自动生成 salt
- `Verify(password, hashed)`：校验密码是否匹配，使用 constant-time 比较防止时序攻击
- `parseHashed()`：内部函数，解析哈希字符串提取参数和原始数据

### Hash Format

```
$pbkdf2-<digest>$i=<iterations>$<salt>$<key>
```
$pbkdf2-<digest>$<iterations>$<salt>$<key>
```

- salt: 16 字节随机数据，base64 编码
- key: 32 字节派生密钥，base64 编码

## Key Design Decisions

- 使用 base64 编码存储 salt 和 key，便于存储和传输
- 依赖 golang.org/x/crypto/pbkdf2，不引入额外依赖
- 使用 `crypto/subtle.ConstantTimeCompare` 防止时序攻击

## Testing

使用 testify 框架，运行测试：

```bash
go test -v ./...
```
