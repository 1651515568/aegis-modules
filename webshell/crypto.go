package webshell

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
)

// shellPasswordKey 从环境变量 AEGIS_SHELL_KEY 派生 AES-256 密钥；
// 未设置时使用内置盐值（比明文存储安全，生产环境应设置环境变量）。
var shellPasswordKey = func() []byte {
	secret := os.Getenv("AEGIS_SHELL_KEY")
	if secret == "" {
		secret = "aegis-webshell-pw-encryption-key-v1-2025"
	}
	h := sha256.Sum256([]byte(secret))
	return h[:]
}()

// shellPWEncrypt 对 Shell 密码进行 AES-256-GCM 加密存储。
// 结果格式："enc:" + base64(nonce[12]+ciphertext+tag[16])
// 已加密（"enc:" 前缀）的值直接返回，避免重复加密。
func shellPWEncrypt(pw string) (string, error) {
	if pw == "" || strings.HasPrefix(pw, "enc:") {
		return pw, nil
	}
	block, err := aes.NewCipher(shellPasswordKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("生成 nonce 失败: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(pw), nil)
	return "enc:" + base64.StdEncoding.EncodeToString(sealed), nil
}

// shellPWDecrypt 解密由 shellPWEncrypt 加密的 Shell 密码。
// 明文（无 "enc:" 前缀，旧数据兼容）直接返回原值。
func shellPWDecrypt(enc string) (string, error) {
	if enc == "" || !strings.HasPrefix(enc, "enc:") {
		return enc, nil // 明文或空值，向后兼容
	}
	data, err := base64.StdEncoding.DecodeString(enc[4:])
	if err != nil {
		return "", fmt.Errorf("密码解码失败: %w", err)
	}
	block, err := aes.NewCipher(shellPasswordKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return "", fmt.Errorf("密码数据长度不足")
	}
	pt, err := gcm.Open(nil, data[:ns], data[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("密码解密失败（密钥不匹配或数据损坏）")
	}
	return string(pt), nil
}

// pkcs7Pad pads data to a multiple of blockSize using PKCS7.
func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - (len(data) % blockSize)
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

// pkcs7Unpad removes PKCS7 padding.
func pkcs7Unpad(data []byte) ([]byte, error) {
	n := len(data)
	if n == 0 {
		return data, nil
	}
	pad := int(data[n-1])
	if pad == 0 || pad > aes.BlockSize || pad > n {
		return nil, fmt.Errorf("invalid PKCS7 padding")
	}
	return data[:n-pad], nil
}

// xorCrypt 对 data 每字节与 key 循环异或（加解密对称）。
// 对应冰蝎 default_xor / default_xor_base64 协议。
func xorCrypt(key, data []byte) []byte {
	out := make([]byte, len(data))
	kl := len(key)
	for i, b := range data {
		out[i] = b ^ key[i%kl]
	}
	return out
}

// aes128ECBEncrypt encrypts plaintext with AES-128-ECB + PKCS7 padding.
// 与冰蝎 v3 PHP shell 中 openssl_encrypt($data, "AES128", $key) 兼容。
func aes128ECBEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	out := make([]byte, len(padded))
	for i := 0; i < len(padded); i += aes.BlockSize {
		block.Encrypt(out[i:i+aes.BlockSize], padded[i:i+aes.BlockSize])
	}
	return out, nil
}

// aes128CBCEncrypt 使用 AES-128-CBC（IV=Key）加密，与 ASPX 自定义 shell 协议兼容。
func aes128CBCEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	out := make([]byte, len(padded))
	iv := key[:aes.BlockSize] // IV = Key（ASPX shell 约定）
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return out, nil
}

// aes256GCMEncrypt 使用 AES-256-GCM 加密，每次请求生成不同的随机 12 字节 nonce。
// 输出格式：nonce(12字节) + ciphertext + tag(16字节)，供调用方 base64 编码后传输。
// 与对应 PHP Shell（aes_gcm 协议）兼容：openssl_decrypt($ct, 'aes-256-gcm', $key, ..., $nonce, $tag)。
//
// ECB 模式的问题：相同明文产生相同密文，流量特征固定，容易被 WAF/IDS 统计特征识别。
// GCM 模式的优势：随机 nonce 使每次密文完全不同，且内置 AEAD 完整性校验。
func aes256GCMEncrypt(key32, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key32)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("生成 GCM nonce 失败: %w", err)
	}
	// gcm.Seal 将 ciphertext+tag 追加到 nonce 后面：nonce || ciphertext || tag
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return sealed, nil
}
