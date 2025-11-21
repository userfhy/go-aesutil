# AesUtil

一个基于 AES-256-CBC + PKCS7 填充的简单加解密工具，包含静态函数和可复用实例两种用法。

## 仓库文件
- [main.go](main.go) — 实现核心加解密逻辑和示例程序（主要符号：[`main.AESUtil`](main.go)、[`main.Encrypt`](main.go)、[`main.Decrypt`](main.go)、[`main.NewAESUtil`](main.go)、[`main.EncryptInstance`](main.go)、[`main.DecryptInstance`](main.go)、[`main.validateKeyIV`](main.go)、[`main.pkcs7Pad`](main.go)、[`main.pkcs7Unpad`](main.go)）。
- [aes_test.go](aes_test.go) — 单元测试用例（包含功能与错误场景测试）。
- [aes_bench_test.go](aes_bench_test.go) — 基准与并发测试。
- [go.mod](go.mod) — 模块文件。

## 特性
- AES-256-CBC 加密/解密。
- PKCS7 填充与校验。
- 提供静态函数（[`main.Encrypt`](main.go)、[`main.Decrypt`](main.go)）和实例方法（通过 [`main.NewAESUtil`](main.go) 创建的 [`main.AESUtil`](main.go) 实例，使用 [`main.EncryptInstance`](main.go)/[`main.DecryptInstance`](main.go)）。
- 明确的 Key/IV 长度验证（由 [`main.validateKeyIV`](main.go] 负责）。
- 包含单元测试与基准测试（见 [aes_test.go](aes_test.go)、[aes_bench_test.go](aes_bench_test.go)）。

## 快速开始

1. 构建
```sh
go build -v
```

2. 运行示例（可执行文件会在当前目录生成）
```sh
./AesUtil
```
示例程序在 [main.go](main.go) 中展示了如何使用实例与静态函数。

3. 在代码中调用
- 静态函数：
  - 加密：调用 [`main.Encrypt`](main.go)
  - 解密：调用 [`main.Decrypt`](main.go)
- 实例模式：
  - 创建实例：[`main.NewAESUtil`](main.go)
  - 加密：[`main.EncryptInstance`](main.go)
  - 解密：[`main.DecryptInstance`](main.go)

示例（伪代码）：
```go
// 创建实例
aesUtil, _ := main.NewAESUtil(key, iv)
ciphertext, _ := aesUtil.EncryptInstance(plain)
plain2, _ := aesUtil.DecryptInstance(ciphertext)

// 或静态用法
ciphertext2, _ := main.Encrypt(plain, key, iv)
plain3, _ := main.Decrypt(ciphertext2, key, iv)
```

## 测试与基准
- 运行全部单元测试：
```sh
go test -v ./ 
```
单元测试位于 [aes_test.go](aes_test.go)。

- 运行基准测试：
```sh
go test -bench=. -benchmem
```
基准测试与并发测试位于 [aes_bench_test.go](aes_bench_test.go)。

## 注意事项
- Key 必须为 32 字节（AES-256），IV 必须为 16 字节（AES 块大小）。长度由 [`main.validateKeyIV`](main.go) 校验。
- 加密输出为标准 Base64 编码，解密函数会对 Base64 解码及 PKCS7 填充进行严格校验（实现位于 [`main.pkcs7Pad`](main.go) / [`main.pkcs7Unpad`](main.go)）。
```
