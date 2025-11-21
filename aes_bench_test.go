package main

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// 使用与单元测试相同的 Key 和 IV
var (
	benchKey = []byte(testKeyStr)
	benchIV  = []byte(testIVStr)
)

// --- 性能基准测试 ---

var benchmarkData = []byte(strings.Repeat("A", 1024)) // 1KB 的数据

// BenchmarkEncryptStatic 测试静态 Encrypt 函数的性能
func BenchmarkEncryptStatic(b *testing.B) {

	for b.Loop() {
		_, _ = Encrypt(benchmarkData, benchKey, benchIV)
	}
}

// BenchmarkDecryptStatic 测试静态 Decrypt 函数的性能
func BenchmarkDecryptStatic(b *testing.B) {
	encrypted, _ := Encrypt(benchmarkData, benchKey, benchIV)

	for b.Loop() {
		_, _ = Decrypt(encrypted, benchKey, benchIV)
	}
}

// BenchmarkEncryptInstance 测试实例 EncryptInstance 函数的性能
func BenchmarkEncryptInstance(b *testing.B) {
	aesUtil, _ := NewAESUtil(benchKey, benchIV)

	for b.Loop() {
		_, _ = aesUtil.EncryptInstance(benchmarkData)
	}
}

// BenchmarkDecryptInstance 测试实例 DecryptInstance 函数的性能
func BenchmarkDecryptInstance(b *testing.B) {
	aesUtil, _ := NewAESUtil(benchKey, benchIV)
	encrypted, _ := aesUtil.EncryptInstance(benchmarkData)

	for b.Loop() {
		_, _ = aesUtil.DecryptInstance(encrypted)
	}
}

// --- 并发测试 ---

// TestAESUtilConcurrency 测试 AESUtil 实例在多个 Goroutine 下的线程安全性。
// CBC模式和NewCipher创建的Block对象是线程安全的，因此实例模式应该也是安全的。
func TestAESUtilConcurrency(t *testing.T) {
	const numGoroutines = 1000
	const iterations = 100

	originalData := "Concurrency Test Data. 这是一个并发测试。"
	data := []byte(originalData)

	aesUtil, err := NewAESUtil(benchKey, benchIV)
	if err != nil {
		t.Fatalf("Failed to create AESUtil: %v", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, numGoroutines*iterations)

	t.Logf("Running concurrency test with %d goroutines and %d iterations each...", numGoroutines, iterations)

	for range numGoroutines {
		wg.Go(func() {
			for range iterations {
				// 1. 加密
				encrypted, err := aesUtil.EncryptInstance(data)
				if err != nil {
					errCh <- fmt.Errorf("Encrypt failed in goroutine: %v", err)
					return
				}

				// 2. 解密
				decrypted, err := aesUtil.DecryptInstance(encrypted)
				if err != nil {
					errCh <- fmt.Errorf("Decrypt failed in goroutine: %v", err)
					return
				}

				// 3. 验证
				if decrypted != originalData {
					errCh <- errors.New("Concurrency test: Decrypted data mismatch")
					return
				}
			}
		})
	}

	wg.Wait()
	close(errCh)

	// 检查是否有错误发生
	for err := range errCh {
		t.Errorf("Concurrency Error: %v", err)
		// 只报告一个错误，避免输出过多
		return
	}

	t.Log("Concurrency test passed successfully.")
}
