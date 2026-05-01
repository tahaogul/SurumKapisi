package signing

import (
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if kp.PrivateKey == nil {
		t.Fatal("private key is nil")
	}
	if kp.PublicKey == nil {
		t.Fatal("public key is nil")
	}
	if kp.PublicPEM == "" {
		t.Error("public PEM is empty")
	}
	if kp.PrivatePEM == "" {
		t.Error("private PEM is empty")
	}
}

func TestSignAndVerify(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	data := []byte("test data to sign")
	sig, err := SignData(kp.PrivateKey, data)
	if err != nil {
		t.Fatalf("SignData failed: %v", err)
	}
	if sig == "" {
		t.Fatal("signature is empty")
	}

	// Verify with correct data
	err = VerifySignature(kp.PublicKey, data, sig)
	if err != nil {
		t.Fatalf("VerifySignature failed for valid signature: %v", err)
	}

	// Verify with wrong data
	err = VerifySignature(kp.PublicKey, []byte("wrong data"), sig)
	if err == nil {
		t.Fatal("VerifySignature should fail for wrong data")
	}
}

func TestSignDeterministic(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	data := []byte("same data")
	sig1, _ := SignData(kp.PrivateKey, data)
	sig2, _ := SignData(kp.PrivateKey, data)

	// RSA PKCS1v15 is deterministic with the same key and data
	if sig1 != sig2 {
		t.Error("Expected deterministic signatures for same data+key")
	}
}

func TestHashSHA256(t *testing.T) {
	hash1 := HashSHA256([]byte("hello"))
	hash2 := HashSHA256([]byte("hello"))
	hash3 := HashSHA256([]byte("world"))

	if hash1 != hash2 {
		t.Error("Same input should produce same hash")
	}
	if hash1 == hash3 {
		t.Error("Different inputs should produce different hashes")
	}
	if len(hash1) != 64 {
		t.Errorf("Expected 64-char hex hash, got %d chars", len(hash1))
	}
}

func TestLoadOrCreateKeyPair(t *testing.T) {
	dir := t.TempDir()

	// First call should create keys
	kp1, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateKeyPair (create) failed: %v", err)
	}

	// Second call should load existing keys
	kp2, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateKeyPair (load) failed: %v", err)
	}

	// Should be the same key
	if kp1.PublicPEM != kp2.PublicPEM {
		t.Error("Loaded key should match created key")
	}
}

func TestLoadKeyPairFromPEM(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	kp2, err := LoadKeyPairFromPEM(kp1.PrivatePEM, kp1.PublicPEM)
	if err != nil {
		t.Fatalf("LoadKeyPairFromPEM failed: %v", err)
	}

	// Sign with original, verify with loaded
	data := []byte("cross-verify test")
	sig, _ := SignData(kp1.PrivateKey, data)
	err = VerifySignature(kp2.PublicKey, data, sig)
	if err != nil {
		t.Fatalf("Cross-verification failed: %v", err)
	}
}
