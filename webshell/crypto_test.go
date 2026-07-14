package webshell

import (
	"bytes"
	"testing"
)

// ─── pkcs7Pad / pkcs7Unpad ───────────────────────────────────────────────────

func TestPKCS7RoundTrip(t *testing.T) {
	cases := [][]byte{
		{},
		{1},
		bytes.Repeat([]byte{0xAA}, 16),
		bytes.Repeat([]byte{0xBB}, 17),
		bytes.Repeat([]byte{0xCC}, 31),
	}
	for _, tc := range cases {
		padded := pkcs7Pad(tc, 16)
		if len(padded)%16 != 0 {
			t.Errorf("padded length %d not multiple of 16", len(padded))
		}
		got, err := pkcs7Unpad(padded)
		if err != nil {
			t.Errorf("unpad error for input len=%d: %v", len(tc), err)
			continue
		}
		if !bytes.Equal(got, tc) {
			t.Errorf("roundtrip mismatch: want %v got %v", tc, got)
		}
	}
}

// ─── xorCrypt ─────────────────────────────────────────────────────────────────

func TestXorCryptSymmetric(t *testing.T) {
	key := []byte("testkey")
	plain := []byte("hello webshell 123")
	enc := xorCrypt(key, plain)
	dec := xorCrypt(key, enc)
	if !bytes.Equal(dec, plain) {
		t.Errorf("xorCrypt roundtrip failed: got %v", dec)
	}
}

// ─── aes128ECBEncrypt ─────────────────────────────────────────────────────────

func TestAES128ECBEncrypt(t *testing.T) {
	key := []byte("1234567890123456") // 16 字节
	plain := []byte("hello aegis!")
	ct, err := aes128ECBEncrypt(key, plain)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}
	if len(ct)%16 != 0 {
		t.Errorf("ciphertext length %d not multiple of 16", len(ct))
	}
	// 相同明文每次输出相同（ECB 无随机性）
	ct2, _ := aes128ECBEncrypt(key, plain)
	if !bytes.Equal(ct, ct2) {
		t.Error("ECB encrypt should be deterministic")
	}
}

// ─── aes128CBCEncrypt ─────────────────────────────────────────────────────────

func TestAES128CBCEncrypt(t *testing.T) {
	key := []byte("abcdefghijklmnop") // 16 字节
	plain := []byte("test aspx payload")
	ct, err := aes128CBCEncrypt(key, plain)
	if err != nil {
		t.Fatalf("CBC encrypt error: %v", err)
	}
	if len(ct)%16 != 0 {
		t.Errorf("CBC ciphertext length %d not multiple of 16", len(ct))
	}
	// CBC 用 IV=Key，相同明文相同密文
	ct2, _ := aes128CBCEncrypt(key, plain)
	if !bytes.Equal(ct, ct2) {
		t.Error("CBC with fixed IV should be deterministic")
	}
}

// ─── shellPWEncrypt / shellPWDecrypt ─────────────────────────────────────────

func TestShellPWEncryptDecrypt(t *testing.T) {
	pw := "my-secret-password"
	enc, err := shellPWEncrypt(pw)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}
	if len(enc) < 4 || enc[:4] != "enc:" {
		t.Errorf("encrypted value should start with 'enc:': got %s", enc[:min(10, len(enc))])
	}
	dec, err := shellPWDecrypt(enc)
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}
	if dec != pw {
		t.Errorf("want %q got %q", pw, dec)
	}
}

func TestShellPWEncryptIdempotent(t *testing.T) {
	pw := "already-encrypted"
	enc, _ := shellPWEncrypt(pw)
	enc2, err := shellPWEncrypt(enc) // 已加密值再次加密应直接返回
	if err != nil {
		t.Fatal(err)
	}
	if enc != enc2 {
		t.Error("double-encrypting should be a no-op")
	}
}

func TestShellPWDecryptPlaintext(t *testing.T) {
	// 旧明文记录（无 enc: 前缀）应直接返回
	plain := "legacy-plaintext"
	got, err := shellPWDecrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	if got != plain {
		t.Errorf("want %q got %q", plain, got)
	}
}

func TestShellPWEncryptEmpty(t *testing.T) {
	enc, err := shellPWEncrypt("")
	if err != nil {
		t.Fatal(err)
	}
	if enc != "" {
		t.Errorf("empty password should return empty, got %q", enc)
	}
}

// ─── deriveKey ────────────────────────────────────────────────────────────────

func TestDeriveKey(t *testing.T) {
	k := deriveKey("aegis")
	if len(k) != 16 {
		t.Errorf("deriveKey should return 16 bytes, got %d", len(k))
	}
	// 幂等
	k2 := deriveKey("aegis")
	if k != k2 {
		t.Error("deriveKey should be deterministic")
	}
	// 不同密码不同 key
	k3 := deriveKey("other")
	if k == k3 {
		t.Error("different passwords should yield different keys")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
