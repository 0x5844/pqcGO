package main

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	"crypto/mlkem"

	kyber "github.com/kudelskisecurity/crystals-go/crystals-kyber"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	ChaChaKeySize          = 32
	ChaChaXNonceSize       = 24
	X25519PublicKeySize    = 32
	X25519PrivateKeySize   = 32
	X25519SharedSecretSize = 32
	Blake2sHashSize        = 32
	KeyExt                 = ".key"
	PubKeyExt              = ".pub"
	EncryptedExt           = ".enc"
	FileFormatVersion      = 2
)

type SecurityLevel int

const (
	Level128 SecurityLevel = iota
	Level192
	Level256
)

func (sl SecurityLevel) String() string {
	switch sl {
	case Level128:
		return "128-bit"
	case Level192:
		return "192-bit"
	case Level256:
		return "256-bit"
	default:
		return "unknown"
	}
}

type HybridKeyPair struct {
	MLKEMPublicKey   []byte
	MLKEMPrivateKey  []byte
	X25519PublicKey  [X25519PublicKeySize]byte
	X25519PrivateKey [X25519PrivateKeySize]byte
	KyberPublicKey   []byte
	KyberPrivateKey  []byte
	SecurityLevel    SecurityLevel
	UseMLKEM         bool
}

type QuantumEngine struct {
	securityLevel SecurityLevel
	useMLKEM      bool
	kyberParams   *kyber.Kyber
}

type EncryptedData struct {
	Version         uint32
	SecurityLevel   uint32
	UseMLKEM        bool
	MLKEMCiphertext []byte
	X25519PublicKey []byte
	KyberCiphertext []byte
	Nonce           []byte
	Ciphertext      []byte
	HMAC            []byte
}

type BenchmarkResult struct {
	Operation     string
	FileSize      int64
	Duration      time.Duration
	Throughput    float64
	MemoryUsed    uint64
	Success       bool
	Error         string
	SecurityLevel string
	Algorithm     string
}

type StressTestConfig struct {
	FileSizes      []int64
	Iterations     int
	Concurrency    int
	CleanupFiles   bool
	SecurityLevels []SecurityLevel
}

var fileCounter int64

func NewQuantumEngine(level SecurityLevel, preferMLKEM bool) *QuantumEngine {
	engine := &QuantumEngine{
		securityLevel: level,
		useMLKEM:      preferMLKEM,
	}

	switch level {
	case Level128:
		engine.kyberParams = kyber.NewKyber512()
	case Level192:
		engine.kyberParams = kyber.NewKyber768()
	case Level256:
		engine.kyberParams = kyber.NewKyber1024()
	default:
		engine.kyberParams = kyber.NewKyber768()
	}

	return engine
}

func deriveKeyBLAKE2s(sharedSecret []byte, info string) ([]byte, error) {
	h, err := blake2s.New256(nil)
	if err != nil {
		return nil, err
	}

	h.Write(sharedSecret)
	h.Write([]byte(info))

	return h.Sum(nil), nil
}

func deriveHybridKey(mlkemSecret, x25519Secret, kyberSecret []byte, info string) ([]byte, error) {
	hkdf := hkdf.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, append(append(mlkemSecret, x25519Secret...), kyberSecret...), nil, []byte(info))

	key := make([]byte, ChaChaKeySize)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, err
	}

	return key, nil
}

func generateFileHMAC(key, data []byte) ([]byte, error) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(key)
		return h
	}, key)
	mac.Write(data)
	return mac.Sum(nil), nil
}

func verifyFileHMAC(key, data, expectedHMAC []byte) bool {
	computedHMAC, err := generateFileHMAC(key, data)
	if err != nil {
		return false
	}
	return hmac.Equal(computedHMAC, expectedHMAC)
}

func (qe *QuantumEngine) GenerateHybridKeyPair() (*HybridKeyPair, error) {
	keyPair := &HybridKeyPair{
		SecurityLevel: qe.securityLevel,
		UseMLKEM:      qe.useMLKEM,
	}

	x25519Private := make([]byte, X25519PrivateKeySize)
	if _, err := rand.Read(x25519Private); err != nil {
		return nil, fmt.Errorf("failed to generate X25519 private key: %w", err)
	}

	x25519Public, err := curve25519.X25519(x25519Private, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to generate X25519 public key: %w", err)
	}

	copy(keyPair.X25519PrivateKey[:], x25519Private)
	copy(keyPair.X25519PublicKey[:], x25519Public)

	if qe.useMLKEM {
		switch qe.securityLevel {
		case Level192:
			dk, err := mlkem.GenerateKey768()
			if err != nil {
				return nil, fmt.Errorf("failed to generate ML-KEM-768 key: %w", err)
			}
			keyPair.MLKEMPrivateKey = dk.Bytes()
			keyPair.MLKEMPublicKey = dk.EncapsulationKey().Bytes()
		case Level256:
			dk, err := mlkem.GenerateKey1024()
			if err != nil {
				return nil, fmt.Errorf("failed to generate ML-KEM-1024 key: %w", err)
			}
			keyPair.MLKEMPrivateKey = dk.Bytes()
			keyPair.MLKEMPublicKey = dk.EncapsulationKey().Bytes()
		default:
			return nil, fmt.Errorf("ML-KEM-512 not supported in Go 1.24")
		}
	}

	kyberPublic, kyberPrivate := qe.kyberParams.KeyGen(nil)
	if kyberPublic == nil || kyberPrivate == nil {
		return nil, fmt.Errorf("failed to generate Kyber fallback keys")
	}
	keyPair.KyberPublicKey = kyberPublic
	keyPair.KyberPrivateKey = kyberPrivate

	return keyPair, nil
}

func (qe *QuantumEngine) SaveHybridKeys(keyPair *HybridKeyPair, baseName string) error {
	privateKeyFile := baseName + KeyExt
	publicKeyFile := baseName + PubKeyExt

	privFile, err := os.Create(privateKeyFile)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer privFile.Close()

	binary.Write(privFile, binary.BigEndian, uint32(FileFormatVersion))
	binary.Write(privFile, binary.BigEndian, uint32(keyPair.SecurityLevel))
	binary.Write(privFile, binary.BigEndian, keyPair.UseMLKEM)

	privFile.Write(keyPair.X25519PrivateKey[:])

	binary.Write(privFile, binary.BigEndian, uint32(len(keyPair.MLKEMPrivateKey)))
	privFile.Write(keyPair.MLKEMPrivateKey)

	binary.Write(privFile, binary.BigEndian, uint32(len(keyPair.KyberPrivateKey)))
	privFile.Write(keyPair.KyberPrivateKey)

	if err := privFile.Chmod(0600); err != nil {
		return fmt.Errorf("failed to set private key permissions: %w", err)
	}

	pubFile, err := os.Create(publicKeyFile)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer pubFile.Close()

	binary.Write(pubFile, binary.BigEndian, uint32(FileFormatVersion))
	binary.Write(pubFile, binary.BigEndian, uint32(keyPair.SecurityLevel))
	binary.Write(pubFile, binary.BigEndian, keyPair.UseMLKEM)

	pubFile.Write(keyPair.X25519PublicKey[:])

	binary.Write(pubFile, binary.BigEndian, uint32(len(keyPair.MLKEMPublicKey)))
	pubFile.Write(keyPair.MLKEMPublicKey)

	binary.Write(pubFile, binary.BigEndian, uint32(len(keyPair.KyberPublicKey)))
	pubFile.Write(keyPair.KyberPublicKey)

	fmt.Printf("Hybrid keys saved:\n")
	fmt.Printf("  Private: %s\n", privateKeyFile)
	fmt.Printf("  Public: %s\n", publicKeyFile)
	fmt.Printf("  Security: %s (%s)\n", keyPair.SecurityLevel.String(),
		map[bool]string{true: "ML-KEM", false: "Kyber"}[keyPair.UseMLKEM])

	return nil
}

func (qe *QuantumEngine) LoadHybridPublicKey(filename string) (*HybridKeyPair, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open public key file: %w", err)
	}
	defer file.Close()

	keyPair := &HybridKeyPair{}

	var version, secLevel uint32
	binary.Read(file, binary.BigEndian, &version)
	binary.Read(file, binary.BigEndian, &secLevel)
	binary.Read(file, binary.BigEndian, &keyPair.UseMLKEM)

	keyPair.SecurityLevel = SecurityLevel(secLevel)

	io.ReadFull(file, keyPair.X25519PublicKey[:])

	var mlkemLen uint32
	binary.Read(file, binary.BigEndian, &mlkemLen)
	if mlkemLen > 0 {
		keyPair.MLKEMPublicKey = make([]byte, mlkemLen)
		io.ReadFull(file, keyPair.MLKEMPublicKey)
	}

	var kyberLen uint32
	binary.Read(file, binary.BigEndian, &kyberLen)
	keyPair.KyberPublicKey = make([]byte, kyberLen)
	io.ReadFull(file, keyPair.KyberPublicKey)

	return keyPair, nil
}

func (qe *QuantumEngine) LoadHybridPrivateKey(filename string) (*HybridKeyPair, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open private key file: %w", err)
	}
	defer file.Close()

	keyPair := &HybridKeyPair{}

	var version, secLevel uint32
	binary.Read(file, binary.BigEndian, &version)
	binary.Read(file, binary.BigEndian, &secLevel)
	binary.Read(file, binary.BigEndian, &keyPair.UseMLKEM)

	keyPair.SecurityLevel = SecurityLevel(secLevel)

	io.ReadFull(file, keyPair.X25519PrivateKey[:])

	var mlkemLen uint32
	binary.Read(file, binary.BigEndian, &mlkemLen)
	if mlkemLen > 0 {
		keyPair.MLKEMPrivateKey = make([]byte, mlkemLen)
		io.ReadFull(file, keyPair.MLKEMPrivateKey)
	}

	var kyberLen uint32
	binary.Read(file, binary.BigEndian, &kyberLen)
	keyPair.KyberPrivateKey = make([]byte, kyberLen)
	io.ReadFull(file, keyPair.KyberPrivateKey)

	return keyPair, nil
}

func (qe *QuantumEngine) HybridEncapsulate(publicKeyPair *HybridKeyPair) (*EncryptedData, []byte, error) {
	encData := &EncryptedData{
		Version:       FileFormatVersion,
		SecurityLevel: uint32(publicKeyPair.SecurityLevel),
		UseMLKEM:      publicKeyPair.UseMLKEM,
	}

	var mlkemSecret, x25519Secret, kyberSecret []byte

	if publicKeyPair.UseMLKEM && len(publicKeyPair.MLKEMPublicKey) > 0 {
		switch publicKeyPair.SecurityLevel {
		case Level192:
			ek, err := mlkem.NewEncapsulationKey768(publicKeyPair.MLKEMPublicKey)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create ML-KEM-768 encapsulation key: %w", err)
			}
			secret, ciphertext := ek.Encapsulate()
			mlkemSecret = secret
			encData.MLKEMCiphertext = ciphertext
		case Level256:
			ek, err := mlkem.NewEncapsulationKey1024(publicKeyPair.MLKEMPublicKey)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create ML-KEM-1024 encapsulation key: %w", err)
			}
			secret, ciphertext := ek.Encapsulate()
			mlkemSecret = secret
			encData.MLKEMCiphertext = ciphertext
		}
	}

	x25519EphemeralPrivate := make([]byte, X25519PrivateKeySize)
	if _, err := rand.Read(x25519EphemeralPrivate); err != nil {
		return nil, nil, fmt.Errorf("failed to generate X25519 ephemeral key: %w", err)
	}

	x25519EphemeralPublic, err := curve25519.X25519(x25519EphemeralPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate X25519 ephemeral public: %w", err)
	}

	x25519Secret, err = curve25519.X25519(x25519EphemeralPrivate, publicKeyPair.X25519PublicKey[:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to perform X25519 key exchange: %w", err)
	}

	encData.X25519PublicKey = x25519EphemeralPublic

	switch publicKeyPair.SecurityLevel {
	case Level128:
		qe.kyberParams = kyber.NewKyber512()
	case Level192:
		qe.kyberParams = kyber.NewKyber768()
	case Level256:
		qe.kyberParams = kyber.NewKyber1024()
	}

	kyberCiphertext, kyberSharedSecret := qe.kyberParams.Encaps(publicKeyPair.KyberPublicKey, nil)
	if kyberCiphertext == nil || kyberSharedSecret == nil {
		return nil, nil, fmt.Errorf("failed to encapsulate Kyber shared secret")
	}
	kyberSecret = kyberSharedSecret
	encData.KyberCiphertext = kyberCiphertext

	encryptionKey, err := deriveHybridKey(mlkemSecret, x25519Secret, kyberSecret, "HYBRID_ENCRYPTION_V2")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive hybrid encryption key: %w", err)
	}

	return encData, encryptionKey, nil
}

func (qe *QuantumEngine) HybridDecapsulate(privateKeyPair *HybridKeyPair, encData *EncryptedData) ([]byte, error) {
	var mlkemSecret, x25519Secret, kyberSecret []byte

	if encData.UseMLKEM && len(encData.MLKEMCiphertext) > 0 {
		switch SecurityLevel(encData.SecurityLevel) {
		case Level192:
			dk, err := mlkem.NewDecapsulationKey768(privateKeyPair.MLKEMPrivateKey)
			if err != nil {
				return nil, fmt.Errorf("failed to create ML-KEM-768 decapsulation key: %w", err)
			}
			secret, err := dk.Decapsulate(encData.MLKEMCiphertext)
			if err != nil {
				return nil, fmt.Errorf("failed to decapsulate ML-KEM-768: %w", err)
			}
			mlkemSecret = secret
		case Level256:
			dk, err := mlkem.NewDecapsulationKey1024(privateKeyPair.MLKEMPrivateKey)
			if err != nil {
				return nil, fmt.Errorf("failed to create ML-KEM-1024 decapsulation key: %w", err)
			}
			secret, err := dk.Decapsulate(encData.MLKEMCiphertext)
			if err != nil {
				return nil, fmt.Errorf("failed to decapsulate ML-KEM-1024: %w", err)
			}
			mlkemSecret = secret
		}
	}

	var err error
	x25519Secret, err = curve25519.X25519(privateKeyPair.X25519PrivateKey[:], encData.X25519PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to perform X25519 key exchange: %w", err)
	}

	switch SecurityLevel(encData.SecurityLevel) {
	case Level128:
		qe.kyberParams = kyber.NewKyber512()
	case Level192:
		qe.kyberParams = kyber.NewKyber768()
	case Level256:
		qe.kyberParams = kyber.NewKyber1024()
	}

	kyberSharedSecret := qe.kyberParams.Decaps(privateKeyPair.KyberPrivateKey, encData.KyberCiphertext)
	if kyberSharedSecret == nil {
		return nil, fmt.Errorf("failed to decapsulate Kyber shared secret")
	}
	kyberSecret = kyberSharedSecret

	encryptionKey, err := deriveHybridKey(mlkemSecret, x25519Secret, kyberSecret, "HYBRID_ENCRYPTION_V2")
	if err != nil {
		return nil, fmt.Errorf("failed to derive hybrid encryption key: %w", err)
	}

	return encryptionKey, nil
}

func (qe *QuantumEngine) EncryptFile(inputFile, outputFile, publicKeyFile string) error {
	publicKeyPair, err := qe.LoadHybridPublicKey(publicKeyFile)
	if err != nil {
		return err
	}

	plaintext, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	encData, encryptionKey, err := qe.HybridEncapsulate(publicKeyPair)
	if err != nil {
		return err
	}

	cipher, err := chacha20poly1305.NewX(encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to create XChaCha20-Poly1305 cipher: %w", err)
	}

	nonce := make([]byte, ChaChaXNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := cipher.Seal(nil, nonce, plaintext, nil)

	encData.Nonce = nonce
	encData.Ciphertext = ciphertext

	hmacKey, err := deriveKeyBLAKE2s(encryptionKey, "FILE_INTEGRITY_V2")
	if err != nil {
		return fmt.Errorf("failed to derive HMAC key: %w", err)
	}

	hmacData := append(append(ciphertext, nonce...), encData.MLKEMCiphertext...)
	hmacData = append(hmacData, encData.X25519PublicKey...)
	hmacData = append(hmacData, encData.KyberCiphertext...)

	encData.HMAC, err = generateFileHMAC(hmacKey, hmacData)
	if err != nil {
		return fmt.Errorf("failed to generate file HMAC: %w", err)
	}

	if err := qe.saveEncryptedData(outputFile, encData); err != nil {
		return fmt.Errorf("failed to save encrypted data: %w", err)
	}

	return nil
}

func (qe *QuantumEngine) DecryptFile(inputFile, outputFile, privateKeyFile string) error {
	privateKeyPair, err := qe.LoadHybridPrivateKey(privateKeyFile)
	if err != nil {
		return err
	}

	encData, err := qe.loadEncryptedData(inputFile)
	if err != nil {
		return fmt.Errorf("failed to load encrypted data: %w", err)
	}

	encryptionKey, err := qe.HybridDecapsulate(privateKeyPair, encData)
	if err != nil {
		return err
	}

	hmacKey, err := deriveKeyBLAKE2s(encryptionKey, "FILE_INTEGRITY_V2")
	if err != nil {
		return fmt.Errorf("failed to derive HMAC key: %w", err)
	}

	hmacData := append(append(encData.Ciphertext, encData.Nonce...), encData.MLKEMCiphertext...)
	hmacData = append(hmacData, encData.X25519PublicKey...)
	hmacData = append(hmacData, encData.KyberCiphertext...)

	if !verifyFileHMAC(hmacKey, hmacData, encData.HMAC) {
		return fmt.Errorf("file integrity verification failed - data may be corrupted or tampered")
	}

	if len(encData.Nonce) != ChaChaXNonceSize {
		return fmt.Errorf("invalid nonce size: expected %d, got %d", ChaChaXNonceSize, len(encData.Nonce))
	}

	cipher, err := chacha20poly1305.NewX(encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to create XChaCha20-Poly1305 cipher: %w", err)
	}

	plaintext, err := cipher.Open(nil, encData.Nonce, encData.Ciphertext, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt data - authentication failed: %w", err)
	}

	if err := os.WriteFile(outputFile, plaintext, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}

func (qe *QuantumEngine) saveEncryptedData(filename string, data *EncryptedData) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	binary.Write(file, binary.BigEndian, data.Version)
	binary.Write(file, binary.BigEndian, data.SecurityLevel)
	binary.Write(file, binary.BigEndian, data.UseMLKEM)

	writeBytes := func(data []byte) error {
		if err := binary.Write(file, binary.BigEndian, uint32(len(data))); err != nil {
			return err
		}
		_, err := file.Write(data)
		return err
	}

	if err := writeBytes(data.MLKEMCiphertext); err != nil {
		return fmt.Errorf("failed to write ML-KEM ciphertext: %w", err)
	}
	if err := writeBytes(data.X25519PublicKey); err != nil {
		return fmt.Errorf("failed to write X25519 public key: %w", err)
	}
	if err := writeBytes(data.KyberCiphertext); err != nil {
		return fmt.Errorf("failed to write Kyber ciphertext: %w", err)
	}
	if err := writeBytes(data.Nonce); err != nil {
		return fmt.Errorf("failed to write nonce: %w", err)
	}
	if err := writeBytes(data.Ciphertext); err != nil {
		return fmt.Errorf("failed to write ciphertext: %w", err)
	}
	if err := writeBytes(data.HMAC); err != nil {
		return fmt.Errorf("failed to write HMAC: %w", err)
	}

	return nil
}

func (qe *QuantumEngine) loadEncryptedData(filename string) (*EncryptedData, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data := &EncryptedData{}

	binary.Read(file, binary.BigEndian, &data.Version)
	binary.Read(file, binary.BigEndian, &data.SecurityLevel)
	binary.Read(file, binary.BigEndian, &data.UseMLKEM)

	readBytes := func() ([]byte, error) {
		var length uint32
		if err := binary.Read(file, binary.BigEndian, &length); err != nil {
			return nil, err
		}
		if length > 100*1024*1024 {
			return nil, fmt.Errorf("invalid data length: %d", length)
		}
		data := make([]byte, length)
		_, err := io.ReadFull(file, data)
		return data, err
	}

	if data.MLKEMCiphertext, err = readBytes(); err != nil {
		return nil, fmt.Errorf("failed to read ML-KEM ciphertext: %w", err)
	}
	if data.X25519PublicKey, err = readBytes(); err != nil {
		return nil, fmt.Errorf("failed to read X25519 public key: %w", err)
	}
	if data.KyberCiphertext, err = readBytes(); err != nil {
		return nil, fmt.Errorf("failed to read Kyber ciphertext: %w", err)
	}
	if data.Nonce, err = readBytes(); err != nil {
		return nil, fmt.Errorf("failed to read nonce: %w", err)
	}
	if data.Ciphertext, err = readBytes(); err != nil {
		return nil, fmt.Errorf("failed to read ciphertext: %w", err)
	}
	if data.HMAC, err = readBytes(); err != nil {
		return nil, fmt.Errorf("failed to read HMAC: %w", err)
	}

	return data, nil
}

func generateTestFile(filename string, size int64) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	buffer := make([]byte, 64*1024)
	remaining := size

	for remaining > 0 {
		chunkSize := int64(len(buffer))
		if remaining < chunkSize {
			chunkSize = remaining
		}

		if _, err := rand.Read(buffer[:chunkSize]); err != nil {
			return err
		}

		if _, err := file.Write(buffer[:chunkSize]); err != nil {
			return err
		}

		remaining -= chunkSize
	}

	return nil
}

func getMemoryUsage() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Alloc
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func getUniqueID() int64 {
	return atomic.AddInt64(&fileCounter, 1)
}

func (qe *QuantumEngine) benchmarkKeyGeneration(iterations int) []BenchmarkResult {
	var results []BenchmarkResult

	for i := 0; i < iterations; i++ {
		startMem := getMemoryUsage()
		startTime := time.Now()

		_, err := qe.GenerateHybridKeyPair()

		duration := time.Since(startTime)
		endMem := getMemoryUsage()

		algorithm := "Kyber"
		if qe.useMLKEM {
			algorithm = "ML-KEM"
		}

		result := BenchmarkResult{
			Operation:     "Hybrid Key Generation",
			FileSize:      0,
			Duration:      duration,
			Throughput:    0,
			MemoryUsed:    endMem - startMem,
			Success:       err == nil,
			SecurityLevel: qe.securityLevel.String(),
			Algorithm:     fmt.Sprintf("Hybrid %s+X25519", algorithm),
		}

		if err != nil {
			result.Error = err.Error()
		}

		results = append(results, result)
	}

	return results
}

func (qe *QuantumEngine) benchmarkEncryption(testFile, publicKeyFile string, fileSize int64, uniqueID int64) BenchmarkResult {
	startMem := getMemoryUsage()
	startTime := time.Now()

	outputFile := fmt.Sprintf("%s.enc.bench.%d", testFile, uniqueID)
	err := qe.EncryptFile(testFile, outputFile, publicKeyFile)

	duration := time.Since(startTime)
	endMem := getMemoryUsage()

	throughput := float64(fileSize) / (1024 * 1024) / duration.Seconds()

	algorithm := "Kyber"
	if qe.useMLKEM {
		algorithm = "ML-KEM"
	}

	result := BenchmarkResult{
		Operation:     "Hybrid Encryption",
		FileSize:      fileSize,
		Duration:      duration,
		Throughput:    throughput,
		MemoryUsed:    endMem - startMem,
		Success:       err == nil,
		SecurityLevel: qe.securityLevel.String(),
		Algorithm:     fmt.Sprintf("Hybrid %s+X25519+XChaCha20", algorithm),
	}

	if err != nil {
		result.Error = err.Error()
	}

	os.Remove(outputFile)
	return result
}

func (qe *QuantumEngine) benchmarkDecryption(testFile, privateKeyFile string, fileSize int64, uniqueID int64) BenchmarkResult {
	encryptedFile := fmt.Sprintf("%s.enc.bench.%d", testFile, uniqueID)
	publicKeyFile := privateKeyFile[:len(privateKeyFile)-4] + ".pub"

	if err := qe.EncryptFile(testFile, encryptedFile, publicKeyFile); err != nil {
		return BenchmarkResult{
			Operation:     "Hybrid Decryption",
			FileSize:      fileSize,
			Success:       false,
			Error:         "Failed to prepare encrypted file: " + err.Error(),
			SecurityLevel: qe.securityLevel.String(),
		}
	}

	startMem := getMemoryUsage()
	startTime := time.Now()

	outputFile := fmt.Sprintf("%s.dec.bench.%d", testFile, uniqueID)
	err := qe.DecryptFile(encryptedFile, outputFile, privateKeyFile)

	duration := time.Since(startTime)
	endMem := getMemoryUsage()

	throughput := float64(fileSize) / (1024 * 1024) / duration.Seconds()

	algorithm := "Kyber"
	if qe.useMLKEM {
		algorithm = "ML-KEM"
	}

	result := BenchmarkResult{
		Operation:     "Hybrid Decryption",
		FileSize:      fileSize,
		Duration:      duration,
		Throughput:    throughput,
		MemoryUsed:    endMem - startMem,
		Success:       err == nil,
		SecurityLevel: qe.securityLevel.String(),
		Algorithm:     fmt.Sprintf("Hybrid %s+X25519+XChaCha20", algorithm),
	}

	if err != nil {
		result.Error = err.Error()
	}

	os.Remove(encryptedFile)
	os.Remove(outputFile)
	return result
}

func (qe *QuantumEngine) runStressTest(config StressTestConfig) {
	fmt.Printf("\n🚀 **Enhanced Post-Quantum Encryption Stress Test**\n")
	fmt.Printf("==================================================\n")
	fmt.Printf("Hybrid KEM: ML-KEM/Kyber + X25519 + XChaCha20-Poly1305\n")
	fmt.Printf("Hash Function: BLAKE2s (performance optimized)\n")
	fmt.Printf("File Integrity: HMAC-BLAKE2s verification\n")
	fmt.Printf("Concurrency: %d threads\n", config.Concurrency)
	fmt.Printf("CPU Cores: %d\n", runtime.NumCPU())
	fmt.Printf("Go Version: %s\n\n", runtime.Version())

	for _, secLevel := range config.SecurityLevels {
		for _, useMLKEM := range []bool{true, false} {
			if useMLKEM && secLevel == Level128 {
				continue
			}

			engine := NewQuantumEngine(secLevel, useMLKEM)

			algorithm := "Kyber"
			if useMLKEM {
				algorithm = "ML-KEM"
			}

			fmt.Printf("\n🔒 **Testing %s Security (%s)**\n", secLevel.String(), algorithm)
			fmt.Printf("=================================\n")

			fmt.Println("🔑 **Generating hybrid test keys...**")
			keyPair, err := engine.GenerateHybridKeyPair()
			if err != nil {
				log.Printf("Failed to generate keys for %s %s: %v", secLevel.String(), algorithm, err)
				continue
			}

			keyBaseName := fmt.Sprintf("stress_test_%s_%s", secLevel.String(), algorithm)
			if err := engine.SaveHybridKeys(keyPair, keyBaseName); err != nil {
				log.Printf("Failed to save keys: %v", err)
				continue
			}

			defer func(baseName string) {
				if config.CleanupFiles {
					os.Remove(baseName + KeyExt)
					os.Remove(baseName + PubKeyExt)
				}
			}(keyBaseName)

			fmt.Println("\n📊 **Hybrid Key Generation Benchmark**")
			keyGenResults := engine.benchmarkKeyGeneration(5)

			var totalKeyGenTime time.Duration
			var keyGenSuccess int
			for _, result := range keyGenResults {
				totalKeyGenTime += result.Duration
				if result.Success {
					keyGenSuccess++
				}
			}
			avgKeyGenTime := totalKeyGenTime / time.Duration(len(keyGenResults))
			fmt.Printf("Average key generation time: %v (%d/%d successful)\n",
				avgKeyGenTime, keyGenSuccess, len(keyGenResults))

			testSizes := []int64{1024, 100 * 1024, 1024 * 1024}

			for _, fileSize := range testSizes {
				fmt.Printf("\n--- Testing %s files ---\n", formatBytes(fileSize))

				testFile := fmt.Sprintf("test_%s_%s_%d.dat", secLevel.String(), algorithm, fileSize)
				fmt.Printf("Generating test file...")
				if err := generateTestFile(testFile, fileSize); err != nil {
					fmt.Printf(" FAILED: %v\n", err)
					continue
				}
				fmt.Printf(" ✓\n")

				fmt.Printf("Sequential encryption...")
				encResult := engine.benchmarkEncryption(testFile, keyBaseName+PubKeyExt, fileSize, getUniqueID())

				if encResult.Success {
					fmt.Printf(" ✓ %.2f MB/s\n", encResult.Throughput)
				} else {
					fmt.Printf(" ✗ %s\n", encResult.Error)
				}

				fmt.Printf("Sequential decryption...")
				decResult := engine.benchmarkDecryption(testFile, keyBaseName+KeyExt, fileSize, getUniqueID())

				if decResult.Success {
					fmt.Printf(" ✓ %.2f MB/s\n", decResult.Throughput)
				} else {
					fmt.Printf(" ✗ %s\n", decResult.Error)
				}

				if config.CleanupFiles {
					os.Remove(testFile)
				}
			}
		}
	}

	fmt.Printf("\n✅ **Enhanced Hybrid Testing Completed!**\n")
	fmt.Printf("🔒 **Security Features:**\n")
	fmt.Printf("  • Hybrid KEM: Classical + Post-Quantum resistance\n")
	fmt.Printf("  • BLAKE2s: High-performance hashing\n")
	fmt.Printf("  • File Integrity: HMAC-based verification\n")
	fmt.Printf("  • Future-Proof: ML-KEM compatibility\n")
}

func main() {
	var (
		generateKeys  = flag.Bool("generate", false, "Generate new hybrid key pair")
		keyName       = flag.String("keyname", "quantum", "Base name for key files")
		encrypt       = flag.String("encrypt", "", "File to encrypt")
		decrypt       = flag.String("decrypt", "", "File to decrypt")
		output        = flag.String("output", "", "Output file (auto-generated if not specified)")
		publicKey     = flag.String("pubkey", "", "Public key file for encryption")
		privateKey    = flag.String("privkey", "", "Private key file for decryption")
		benchmark     = flag.Bool("benchmark", false, "Run performance benchmark and stress test")
		securityLevel = flag.String("level", "192", "Security level: 128, 192, or 256 bits")
		useMLKEM      = flag.Bool("mlkem", true, "Use Go 1.24 ML-KEM (vs legacy Kyber)")
		help          = flag.Bool("help", false, "Show help message")
	)

	flag.Parse()

	if *help {
		fmt.Println("Enhanced Post-Quantum Secure Encryption Engine")
		fmt.Println("==============================================")
		fmt.Println("Hybrid KEM: ML-KEM/Kyber + X25519 + XChaCha20-Poly1305")
		fmt.Println("Hash: BLAKE2s | Integrity: HMAC-BLAKE2s | Future-Ready: ML-KEM")
		fmt.Println("\nSecurity Levels:")
		fmt.Println("  128-bit: Kyber512 (legacy only)")
		fmt.Println("  192-bit: Kyber768/ML-KEM-768 (recommended)")
		fmt.Println("  256-bit: Kyber1024/ML-KEM-1024")
		fmt.Println("\nUsage:")
		fmt.Println("  Generate keys:")
		fmt.Println("    go run main.go -generate -keyname mykeys -level 192 -mlkem")
		fmt.Println("  Encrypt file:")
		fmt.Println("    go run main.go -encrypt data.txt -pubkey mykeys.pub")
		fmt.Println("  Decrypt file:")
		fmt.Println("    go run main.go -decrypt data.txt.enc -privkey mykeys.key")
		fmt.Println("  Run benchmarks:")
		fmt.Println("    go run main.go -benchmark")
		flag.PrintDefaults()
		return
	}

	var level SecurityLevel
	switch *securityLevel {
	case "128":
		level = Level128
	case "192":
		level = Level192
	case "256":
		level = Level256
	default:
		log.Fatalf("Invalid security level: %s (use 128, 192, or 256)", *securityLevel)
	}

	if *useMLKEM && level == Level128 {
		log.Printf("Warning: ML-KEM-512 not supported in Go 1.24, falling back to Kyber512")
		*useMLKEM = false
	}

	engine := NewQuantumEngine(level, *useMLKEM)

	switch {
	case *benchmark:
		config := StressTestConfig{
			FileSizes:      []int64{1024, 100 * 1024, 1024 * 1024},
			Iterations:     2,
			Concurrency:    runtime.NumCPU(),
			CleanupFiles:   true,
			SecurityLevels: []SecurityLevel{Level192, Level256},
		}
		engine.runStressTest(config)

	case *generateKeys:
		algorithm := "Kyber"
		if *useMLKEM {
			algorithm = "ML-KEM"
		}
		fmt.Printf("Generating hybrid key pair: %s %s + X25519...\n", level.String(), algorithm)

		keyPair, err := engine.GenerateHybridKeyPair()
		if err != nil {
			log.Fatalf("Key generation failed: %v", err)
		}

		if err := engine.SaveHybridKeys(keyPair, *keyName); err != nil {
			log.Fatalf("Failed to save keys: %v", err)
		}

		fmt.Printf("Hybrid key pair generated successfully!\n")
		fmt.Printf("Security level: %s\n", level.String())
		fmt.Printf("Algorithm: Hybrid %s + X25519 + XChaCha20-Poly1305\n", algorithm)
		fmt.Printf("Features: BLAKE2s hashing + HMAC integrity verification\n")

	case *encrypt != "":
		if *publicKey == "" {
			*publicKey = *keyName + PubKeyExt
		}

		outputFile := *output
		if outputFile == "" {
			outputFile = *encrypt + EncryptedExt
		}

		fmt.Printf("Encrypting %s with hybrid post-quantum encryption...\n", *encrypt)
		if err := engine.EncryptFile(*encrypt, outputFile, *publicKey); err != nil {
			log.Fatalf("Encryption failed: %v", err)
		}
		fmt.Printf("File encrypted successfully: %s -> %s\n", *encrypt, outputFile)
		fmt.Printf("Security: Hybrid KEM + File integrity verification\n")

	case *decrypt != "":
		if *privateKey == "" {
			*privateKey = *keyName + KeyExt
		}

		outputFile := *output
		if outputFile == "" {
			ext := filepath.Ext(*decrypt)
			if ext == EncryptedExt {
				outputFile = (*decrypt)[:len(*decrypt)-len(ext)] + ".decrypted"
			} else {
				outputFile = *decrypt + ".decrypted"
			}
		}

		fmt.Printf("Decrypting %s with hybrid post-quantum decryption...\n", *decrypt)
		if err := engine.DecryptFile(*decrypt, outputFile, *privateKey); err != nil {
			log.Fatalf("Decryption failed: %v", err)
		}
		fmt.Printf("File decrypted successfully: %s -> %s\n", *decrypt, outputFile)
		fmt.Printf("Verification: File integrity confirmed\n")

	default:
		fmt.Println("Enhanced Post-Quantum Encryption Engine")
		fmt.Println("======================================")
		fmt.Println("Use -help for usage information.")
		fmt.Println("\nQuick start:")
		fmt.Println("  1. Generate keys: go run main.go -generate -level 192")
		fmt.Println("  2. Encrypt file: go run main.go -encrypt yourfile.txt")
		fmt.Println("  3. Decrypt file: go run main.go -decrypt yourfile.txt.enc")
		fmt.Println("  4. Run benchmarks: go run main.go -benchmark")
		fmt.Printf("\nCurrent: %s security with %s\n", level.String(),
			map[bool]string{true: "ML-KEM", false: "Kyber"}[*useMLKEM])
	}
}
