package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// AES 块大小，固定为 16 字节 (128 bits)
const aesBlockSize = aes.BlockSize

// AES256KeySize 定义了 AES-256 所需的密钥长度 (32 字节 / 256 bits)
const aes256KeySize = 32

// AESUtil 结构体：用于高性能、可复用的加解密操作。
type AESUtil struct {
	key       []byte
	iv        []byte
	cipherBlk cipher.Block
}

func init() {
	// 设置时区，以便 main 函数中的时间戳格式化正确
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		panic(fmt.Errorf("加载时区失败: %w", err))
	}
	time.Local = loc
}

// validateKeyIV 验证密钥和 IV 的长度是否符合 AES-256-CBC 的要求。
func validateKeyIV(key []byte, iv []byte) error {
	if len(key) != aes256KeySize {
		return fmt.Errorf("密钥长度必须是 %d 字节 (256 bits)，当前为: %d", aes256KeySize, len(key))
	}
	if len(iv) != aesBlockSize {
		return fmt.Errorf("初始向量 (IV) 长度必须是 %d 字节 (128 bits)，当前为: %d", aesBlockSize, len(iv))
	}
	return nil
}

// pkcs7Pad 执行 PKCS7 填充。
func pkcs7Pad(data []byte) []byte {
	padding := aesBlockSize - (len(data) % aesBlockSize)
	padtext := make([]byte, padding)
	// 填充字节的值等于填充长度
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

// pkcs7Unpad 移除 PKCS7 填充，并进行有效性检查。
func pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 || length%aesBlockSize != 0 {
		return nil, errors.New("解密数据长度无效或不是块大小的倍数")
	}

	padding := int(data[length-1])
	if padding == 0 || padding > aesBlockSize {
		return nil, errors.New("无效的填充值")
	}

	start := length - padding
	if start < 0 {
		return nil, errors.New("填充值超出数据长度")
	}

	// 验证所有填充字节是否一致
	for i := start; i < length; i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("填充字节序列无效")
		}
	}

	return data[:start], nil
}

// Encrypt performs AES-256-CBC encryption.
// 密文使用 Base64 标准编码 (StdEncoding) 导出，以提高与大多数在线工具的兼容性。
func Encrypt(data []byte, key []byte, iv []byte) (string, error) {
	if err := validateKeyIV(key, iv); err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("创建 AES 密码块失败: %w", err)
	}

	paddedData := pkcs7Pad(data)
	encrypted := make([]byte, len(paddedData))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encrypted, paddedData)

	// 使用标准 Base64 编码
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// Decrypt performs AES-256-CBC decryption.
func Decrypt(encryptedData string, key []byte, iv []byte) (string, error) {
	if err := validateKeyIV(key, iv); err != nil {
		return "", err
	}

	// 使用标准 Base64 解码
	decoded, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("Base64 解码失败: %w", err)
	}

	if len(decoded) == 0 || len(decoded)%aesBlockSize != 0 {
		return "", errors.New("解密数据长度无效: 不是块大小的倍数")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("创建 AES 密码块失败: %w", err)
	}

	// 解密操作，直接在 decoded 缓冲区上进行
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decoded, decoded)

	unpadded, err := pkcs7Unpad(decoded)
	if err != nil {
		return "", fmt.Errorf("移除填充失败: %w", err)
	}

	return string(unpadded), nil
}

// NewAESUtil 创建并返回一个 AESUtil 实例。
func NewAESUtil(key []byte, iv []byte) (*AESUtil, error) {
	if err := validateKeyIV(key, iv); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("创建 AES 密码块失败: %w", err)
	}

	// 复制 key 和 iv，防止外部修改
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	ivCopy := make([]byte, len(iv))
	copy(ivCopy, iv)

	return &AESUtil{
		key:       keyCopy,
		iv:        ivCopy,
		cipherBlk: block, // 缓存密码块
	}, nil
}

// EncryptInstance 使用实例的密钥和 IV 进行加密。
func (a *AESUtil) EncryptInstance(data []byte) (string, error) {
	paddedData := pkcs7Pad(data)
	encrypted := make([]byte, len(paddedData))

	mode := cipher.NewCBCEncrypter(a.cipherBlk, a.iv)
	mode.CryptBlocks(encrypted, paddedData)

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecryptInstance 使用实例的密钥和 IV 进行解密。
func (a *AESUtil) DecryptInstance(encryptedData string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("Base64 解码失败: %w", err)
	}

	if len(decoded) == 0 || len(decoded)%aesBlockSize != 0 {
		return "", errors.New("解密数据长度无效: 不是块大小的倍数")
	}

	mode := cipher.NewCBCDecrypter(a.cipherBlk, a.iv)
	mode.CryptBlocks(decoded, decoded)

	unpadded, err := pkcs7Unpad(decoded)
	if err != nil {
		return "", fmt.Errorf("移除填充失败: %w", err)
	}

	return string(unpadded), nil
}

func main() {
	// 示例密钥 (32 字节 / 256 bits)
	key := []byte("imwl8sot7u8zvdcr6wvbwcmhrwpfb3rs")
	// 示例初始向量 IV (16 字节 / 128 bits)
	iv := []byte("lgd73e8vc7ah52u9")

	data := []byte("AES-256-CBC测试数据，当前时间为：" + time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println("--- 配置参数 ---")
	fmt.Printf("模式: AES-256-CBC with PKCS7 Padding\n")
	fmt.Printf("密钥 (Key): %s (长度: %d 字节)\n", string(key), len(key))
	fmt.Printf("初始向量 (IV): %s (长度: %d 字节)\n", string(iv), len(iv))
	fmt.Println("原始数据：", string(data))
	fmt.Println("-----------------")

	// 推荐用法：创建并使用 AESUtil 实例
	aesUtil, err := NewAESUtil(key, iv)
	if err != nil {
		panic(err)
	}

	fmt.Println("--- 实例模式测试 ---")

	encryptedInstance, err := aesUtil.EncryptInstance(data)
	if err != nil {
		panic(err)
	}
	fmt.Println("加密结果 (Base64 Standard)：", encryptedInstance)

	decryptedInstance, err := aesUtil.DecryptInstance(encryptedInstance)
	if err != nil {
		panic(err)
	}
	fmt.Println("解密结果：", decryptedInstance)
	fmt.Println("-----------------")

	// 静态函数用法
	fmt.Println("--- 静态函数模式测试 ---")
	encryptedStatic, err := Encrypt(data, key, iv)
	if err != nil {
		panic(err)
	}
	fmt.Println("加密结果 (Base64 Standard)：", encryptedStatic)
	fmt.Println("-----------------")

	decryptedStatic, err := Decrypt(encryptedStatic, key, iv)
	if err != nil {
		panic(err)
	}
	fmt.Println("解密结果：", decryptedStatic)
}
