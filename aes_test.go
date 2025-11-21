package main

import (
	"strings"
	"testing"
)

// 定义测试用的 Key 和 IV
const (
	testKeyStr = "imwl8sot7u8zvdcr6wvbwcmhrwpfb3rs" // 32 bytes (256 bits)
	testIVStr  = "lgd73e8vc7ah52u9"                 // 16 bytes (128 bits)
)

var (
	testKey = []byte(testKeyStr)
	testIV  = []byte(testIVStr)
)

// --- 基础加解密测试 ---

// TestEncryptDecryptStatic 测试静态 Encrypt 和 Decrypt 函数的完整流程。
func TestEncryptDecryptStatic(t *testing.T) {
	originalData := "Hello, AES-256-CBC World! 你好，世界！1234567890"
	data := []byte(originalData)

	// 1. 加密
	encrypted, err := Encrypt(data, testKey, testIV)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if encrypted == originalData {
		t.Fatal("Encrypted data is the same as original data, encryption failed.")
	}

	// 2. 解密
	decrypted, err := Decrypt(encrypted, testKey, testIV)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// 3. 验证结果
	if decrypted != originalData {
		t.Errorf("Decrypted data mismatch.\nExpected: %s\nGot:      %s", originalData, decrypted)
	}
}

// TestEncryptDecryptInstance 测试实例方法 EncryptInstance 和 DecryptInstance 的完整流程。
func TestEncryptDecryptInstance(t *testing.T) {
	originalData := "Instance Test Data. 测试实例模式。"
	data := []byte(originalData)

	aesUtil, err := NewAESUtil(testKey, testIV)
	if err != nil {
		t.Fatalf("NewAESUtil failed: %v", err)
	}

	// 1. 加密
	encrypted, err := aesUtil.EncryptInstance(data)
	if err != nil {
		t.Fatalf("EncryptInstance failed: %v", err)
	}

	// 2. 解密
	decrypted, err := aesUtil.DecryptInstance(encrypted)
	if err != nil {
		t.Fatalf("DecryptInstance failed: %v", err)
	}

	// 3. 验证结果
	if decrypted != originalData {
		t.Errorf("Instance Decrypt mismatch.\nExpected: %s\nGot:      %s", originalData, decrypted)
	}
}

// --- 错误场景测试 ---

// TestInvalidKeyIVLength 测试 Key 和 IV 长度验证。
func TestInvalidKeyIVLength(t *testing.T) {
	// 短 Key (预期失败)
	shortKey := []byte("short")
	if _, err := Encrypt(nil, shortKey, testIV); err == nil || !strings.Contains(err.Error(), "密钥长度必须是 32 字节") {
		t.Errorf("Expected key length error, got: %v", err)
	}

	// 长 Key (预期失败)
	longKey := []byte("imwl8sot7u8zvdcr6wvbwcmhrwpfb3rs000") // 35 bytes
	if _, err := Encrypt(nil, longKey, testIV); err == nil || !strings.Contains(err.Error(), "密钥长度必须是 32 字节") {
		t.Errorf("Expected key length error, got: %v", err)
	}

	// 短 IV (预期失败)
	shortIV := []byte("short")
	if _, err := Encrypt(nil, testKey, shortIV); err == nil || !strings.Contains(err.Error(), "初始向量 (IV) 长度必须是 16 字节") {
		t.Errorf("Expected IV length error, got: %v", err)
	}
}

// TestInvalidEncryptedData 测试无效的密文输入。
func TestInvalidEncryptedData(t *testing.T) {
	aesUtil, err := NewAESUtil(testKey, testIV)
	if err != nil {
		t.Fatalf("NewAESUtil failed: %v", err)
	}

	testCases := []struct {
		name    string
		data    string
		wantErr bool
		errMsg  string
	}{
		// 场景 1: Base64 格式错误 (Go会先报 Base64 错误)
		{"Invalid Base64 Format", "!!!not-base64!!!", true, "Base64 解码失败"},

		// 场景 2: 有效 Base64，但解码后长度不是块大小的倍数 (Expected: 解密数据长度无效)
		// "AA==" 解码后是 1 字节
		{"Valid Base64, Bad Length", "AA==", true, "解密数据长度无效"},

		// 场景 3: 长度是块大小的倍数 (32字节)，但内容随机，解密后导致 PKCS7 填充校验失败
		// "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" (44个字符) 解码后是 32 字节。
		{"Valid Length, Bad Padding", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", true, "移除填充失败"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 静态函数测试
			_, err := Decrypt(tc.data, testKey, testIV)
			if (err != nil) != tc.wantErr {
				t.Errorf("Static Decrypt expected error %v, got %v", tc.wantErr, err)
			}
			// 修正后的断言：检查错误信息是否包含预期的子字符串
			if tc.wantErr && err != nil && !strings.Contains(err.Error(), tc.errMsg) {
				t.Errorf("Static Decrypt expected error message to contain '%s', got: %v", tc.errMsg, err)
			}

			// 实例函数测试
			_, err = aesUtil.DecryptInstance(tc.data)
			if (err != nil) != tc.wantErr {
				t.Errorf("Instance Decrypt expected error %v, got %v", tc.wantErr, err)
			}
			// 修正后的断言：检查错误信息是否包含预期的子字符串
			if tc.wantErr && err != nil && !strings.Contains(err.Error(), tc.errMsg) {
				t.Errorf("Instance Decrypt expected error message to contain '%s', got: %v", tc.errMsg, err)
			}
		})
	}
}

// TestEmptyData 测试空数据的处理
func TestEmptyData(t *testing.T) {
	emptyData := []byte("")

	encrypted, err := Encrypt(emptyData, testKey, testIV)
	if err != nil {
		t.Fatalf("Encrypt empty data failed: %v", err)
	}

	// 空数据加密后会被填充到 16 字节，Base64 编码后为 24 个字符
	if len(encrypted) != 24 {
		t.Errorf("Expected encrypted empty data length 24, got %d", len(encrypted))
	}

	decrypted, err := Decrypt(encrypted, testKey, testIV)
	if err != nil {
		t.Fatalf("Decrypt empty data failed: %v", err)
	}

	if decrypted != string(emptyData) {
		t.Errorf("Decrypted empty data mismatch. Expected: '%s', Got: '%s'", string(emptyData), decrypted)
	}
}
