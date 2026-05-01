package signing

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// KeyPair holds an RSA key pair
type KeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	PublicPEM  string
	PrivatePEM string
}

// GenerateKeyPair creates a new RSA-2048 key pair
func GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		PublicPEM:  string(pubPEM),
		PrivatePEM: string(privPEM),
	}, nil
}

// SignData signs data with the private key (SHA256 + RSA PKCS#1 v1.5)
func SignData(privateKey *rsa.PrivateKey, data []byte) (string, error) {
	hash := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign data: %w", err)
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// VerifySignature verifies a signature with the public key
func VerifySignature(publicKey *rsa.PublicKey, data []byte, signatureB64 string) error {
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}
	hash := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature)
}

// HashSHA256 computes SHA256 of data and returns hex string
func HashSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

// HashFileSHA256 computes SHA256 of a file
func HashFileSHA256(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}
	return HashSHA256(data), nil
}

// LoadOrCreateKeyPair loads an existing key pair from disk, or creates a new one
func LoadOrCreateKeyPair(keyDir string) (*KeyPair, error) {
	privPath := filepath.Join(keyDir, "private.pem")
	pubPath := filepath.Join(keyDir, "public.pem")

	// Try to load existing keys
	privData, err := os.ReadFile(privPath)
	if err == nil {
		pubData, err := os.ReadFile(pubPath)
		if err == nil {
			return LoadKeyPairFromPEM(string(privData), string(pubData))
		}
	}

	// Generate new key pair
	kp, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	// Save to disk
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}

	if err := os.WriteFile(privPath, []byte(kp.PrivatePEM), 0600); err != nil {
		return nil, fmt.Errorf("failed to write private key: %w", err)
	}

	if err := os.WriteFile(pubPath, []byte(kp.PublicPEM), 0644); err != nil {
		return nil, fmt.Errorf("failed to write public key: %w", err)
	}

	return kp, nil
}

// LoadKeyPairFromPEM loads a key pair from PEM strings
func LoadKeyPairFromPEM(privatePEM, publicPEM string) (*KeyPair, error) {
	block, _ := pem.Decode([]byte(privatePEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		PublicPEM:  publicPEM,
		PrivatePEM: privatePEM,
	}, nil
}
