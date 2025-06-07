package main

import (
	"bytes"
	"crypto/cipher"
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
	"time"

	"crypto/mlkem"

	kyber "github.com/kudelskisecurity/crystals-go/crystals-kyber"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20"
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
	StreamChunkSize        = 64 * 1024
	KeyExt                 = ".key"
	PubKeyExt              = ".pub"
	EncryptedExt           = ".enc"
	FileFormatVersion      = 3
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
			return nil, fmt.Errorf("ML-KEM-512 not supported")
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
	encryptionKey, err := deriveHybridKey(mlkemSecret, x25519Secret, kyberSecret, "HYBRID_ENCRYPTION_V3")
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
	encryptionKey, err := deriveHybridKey(mlkemSecret, x25519Secret, kyberSecret, "HYBRID_ENCRYPTION_V3")
	if err != nil {
		return nil, fmt.Errorf("failed to derive hybrid encryption key: %w", err)
	}
	return encryptionKey, nil
}

func (qe *QuantumEngine) saveEncryptedHeader(w io.Writer, data *EncryptedData) error {
	if err := binary.Write(w, binary.BigEndian, data.Version); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, data.SecurityLevel); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, data.UseMLKEM); err != nil {
		return err
	}
	writeBytes := func(d []byte) error {
		if err := binary.Write(w, binary.BigEndian, uint32(len(d))); err != nil {
			return err
		}
		_, err := w.Write(d)
		return err
	}
	if err := writeBytes(data.MLKEMCiphertext); err != nil {
		return err
	}
	if err := writeBytes(data.X25519PublicKey); err != nil {
		return err
	}
	if err := writeBytes(data.KyberCiphertext); err != nil {
		return err
	}
	return writeBytes(data.Nonce)
}

func (qe *QuantumEngine) loadEncryptedHeader(r io.Reader) (*EncryptedData, int64, error) {
	data := &EncryptedData{}
	var bytesRead int64
	read := func(d interface{}) error {
		err := binary.Read(r, binary.BigEndian, d)
		if err == nil {
			bytesRead += int64(binary.Size(d))
		}
		return err
	}
	if err := read(&data.Version); err != nil {
		return nil, bytesRead, err
	}
	if err := read(&data.SecurityLevel); err != nil {
		return nil, bytesRead, err
	}
	if err := read(&data.UseMLKEM); err != nil {
		return nil, bytesRead, err
	}
	readBytes := func() ([]byte, error) {
		var length uint32
		if err := read(&length); err != nil {
			return nil, err
		}
		buf := make([]byte, length)
		if n, err := io.ReadFull(r, buf); err != nil {
			bytesRead += int64(n)
			return nil, err
		}
		bytesRead += int64(length)
		return buf, nil
	}
	var err error
	if data.MLKEMCiphertext, err = readBytes(); err != nil {
		return nil, bytesRead, err
	}
	if data.X25519PublicKey, err = readBytes(); err != nil {
		return nil, bytesRead, err
	}
	if data.KyberCiphertext, err = readBytes(); err != nil {
		return nil, bytesRead, err
	}
	if data.Nonce, err = readBytes(); err != nil {
		return nil, bytesRead, err
	}
	return data, bytesRead, nil
}

func (qe *QuantumEngine) EncryptFile(inputFile, outputFile, publicKeyFile string) error {
	publicKeyPair, err := qe.LoadHybridPublicKey(publicKeyFile)
	if err != nil {
		return err
	}
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inFile.Close()
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()
	encData, encryptionKey, err := qe.HybridEncapsulate(publicKeyPair)
	if err != nil {
		return err
	}
	nonce := make([]byte, ChaChaXNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}
	encData.Nonce = nonce
	hmacKey, err := deriveKeyBLAKE2s(encryptionKey, "FILE_INTEGRITY_V3_STREAM")
	if err != nil {
		return fmt.Errorf("failed to derive HMAC key: %w", err)
	}
	streamCipher, err := chacha20.NewUnauthenticatedCipher(encryptionKey, nonce)
	if err != nil {
		return fmt.Errorf("failed to create stream cipher: %w", err)
	}
	mac := hmac.New(func() hash.Hash { h, _ := blake2s.New256(nil); return h }, hmacKey)
	headerBuf := new(bytes.Buffer)
	if err := qe.saveEncryptedHeader(headerBuf, encData); err != nil {
		return fmt.Errorf("failed to serialize header: %w", err)
	}
	if _, err := io.MultiWriter(outFile, mac).Write(headerBuf.Bytes()); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	buf := make([]byte, StreamChunkSize)
	for {
		n, err := inFile.Read(buf)
		if n > 0 {
			encryptedChunk := make([]byte, n)
			streamCipher.XORKeyStream(encryptedChunk, buf[:n])
			if _, writeErr := outFile.Write(encryptedChunk); writeErr != nil {
				return fmt.Errorf("failed to write ciphertext chunk: %w", writeErr)
			}
			if _, writeErr := mac.Write(encryptedChunk); writeErr != nil {
				return fmt.Errorf("failed to write to hmac: %w", writeErr)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read from input file: %w", err)
		}
	}
	if _, err := outFile.Write(mac.Sum(nil)); err != nil {
		return fmt.Errorf("failed to write HMAC: %w", err)
	}
	return nil
}

func (qe *QuantumEngine) DecryptFile(inputFile, outputFile, privateKeyFile string) (err error) {
	privateKeyPair, err := qe.LoadHybridPrivateKey(privateKeyFile)
	if err != nil {
		return err
	}
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inFile.Close()
	fileInfo, err := inFile.Stat()
	if err != nil {
		return err
	}
	fileSize := fileInfo.Size()
	if fileSize < Blake2sHashSize {
		return fmt.Errorf("input file is too small to be valid")
	}
	encData, headerSize, err := qe.loadEncryptedHeader(inFile)
	if err != nil {
		return fmt.Errorf("failed to load encrypted header: %w", err)
	}
	encryptionKey, err := qe.HybridDecapsulate(privateKeyPair, encData)
	if err != nil {
		return err
	}
	hmacKey, err := deriveKeyBLAKE2s(encryptionKey, "FILE_INTEGRITY_V3_STREAM")
	if err != nil {
		return fmt.Errorf("failed to derive HMAC key: %w", err)
	}
	if _, err := inFile.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek in input file: %w", err)
	}
	contentReader := io.LimitReader(inFile, fileSize-Blake2sHashSize)
	mac := hmac.New(func() hash.Hash { h, _ := blake2s.New256(nil); return h }, hmacKey)
	verifyingReader := io.TeeReader(contentReader, mac)
	if _, err := io.CopyN(io.Discard, verifyingReader, headerSize); err != nil {
		return fmt.Errorf("failed to read past header for verification: %w", err)
	}
	outTmpFile, err := os.Create(outputFile + ".tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary output file: %w", err)
	}
	defer func() {
		outTmpFile.Close()
		if err != nil {
			os.Remove(outputFile + ".tmp")
		}
	}()
	streamCipher, err := chacha20.NewUnauthenticatedCipher(encryptionKey, encData.Nonce)
	if err != nil {
		return fmt.Errorf("failed to create stream cipher: %w", err)
	}
	decryptingReader := &cipher.StreamReader{S: streamCipher, R: verifyingReader}
	if _, err := io.Copy(outTmpFile, decryptingReader); err != nil {
		return fmt.Errorf("decryption failed during copy: %w", err)
	}
	expectedHMAC := make([]byte, Blake2sHashSize)
	if _, err := inFile.Read(expectedHMAC); err != nil {
		return fmt.Errorf("failed to read expected HMAC from file: %w", err)
	}
	computedHMAC := mac.Sum(nil)
	if !hmac.Equal(computedHMAC, expectedHMAC) {
		return fmt.Errorf("file integrity verification failed: HMAC mismatch")
	}
	outTmpFile.Close()
	if err := os.Rename(outputFile+".tmp", outputFile); err != nil {
		return fmt.Errorf("failed to rename temporary file: %w", err)
	}
	return nil
}

func generateTestFile(filename string, size int64) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := io.CopyN(file, rand.Reader, size); err != nil {
		return fmt.Errorf("failed to write random data to test file: %w", err)
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

func (qe *QuantumEngine) benchmarkOperation(op, testFile, keyFile string, fileSize int64) BenchmarkResult {
	startMem := getMemoryUsage()
	startTime := time.Now()
	var err error
	outputFile := testFile + ".bench"
	switch op {
	case "encrypt":
		err = qe.EncryptFile(testFile, outputFile, keyFile)
	case "decrypt":
		err = qe.DecryptFile(testFile, outputFile, keyFile)
	}
	duration := time.Since(startTime)
	endMem := getMemoryUsage()
	os.Remove(outputFile)
	throughput := 0.0
	if duration > 0 {
		throughput = float64(fileSize) / duration.Seconds() / (1024 * 1024)
	}
	algorithm := "Kyber"
	if qe.useMLKEM {
		algorithm = "ML-KEM"
	}
	result := BenchmarkResult{
		Operation:     "Hybrid " + op,
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
	return result
}

func (qe *QuantumEngine) runStressTest(config StressTestConfig) {
	fmt.Printf("\n🚀 **Post-Quantum Stream Encryption Stress Test**\n")
	fmt.Printf("==================================================\n")
	fmt.Printf("Hybrid KEM: ML-KEM/Kyber + X25519 | Stream Cipher: XChaCha20\n")
	fmt.Printf("Hash: BLAKE2s | Integrity: HMAC-BLAKE2s (Header + Ciphertext)\n")
	fmt.Printf("Concurrency: %d threads | CPU Cores: %d | Go Version: %s\n\n", config.Concurrency, runtime.NumCPU(), runtime.Version())
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
			keyBaseName := fmt.Sprintf("stress_test_%s_%s", secLevel.String(), algorithm)
			keyPair, err := engine.GenerateHybridKeyPair()
			if err != nil {
				log.Printf("FAIL: Key generation for %s %s: %v", secLevel.String(), algorithm, err)
				continue
			}
			if err := engine.SaveHybridKeys(keyPair, keyBaseName); err != nil {
				log.Printf("FAIL: Key saving: %v", err)
				continue
			}
			if config.CleanupFiles {
				defer os.Remove(keyBaseName + KeyExt)
				defer os.Remove(keyBaseName + PubKeyExt)
			}
			for _, fileSize := range config.FileSizes {
				fmt.Printf("\n--- Testing %s files ---\n", formatBytes(fileSize))
				testFile := fmt.Sprintf("test_%s.dat", formatBytes(fileSize))
				fmt.Printf("Generating test file...")
				if err := generateTestFile(testFile, fileSize); err != nil {
					fmt.Printf(" FAILED: %v\n", err)
					continue
				}
				fmt.Printf(" ✓\n")
				encryptedFile := testFile + ".enc"
				encResult := qe.benchmarkOperation("encrypt", testFile, keyBaseName+PubKeyExt, fileSize)
				fmt.Printf("Stream encryption...")
				if encResult.Success {
					fmt.Printf(" ✓ %.2f MB/s\n", encResult.Throughput)
				} else {
					fmt.Printf(" ✗ %s\n", encResult.Error)
					os.Remove(testFile)
					continue
				}
				if err := qe.EncryptFile(testFile, encryptedFile, keyBaseName+PubKeyExt); err != nil {
					log.Printf("FAIL: Could not create file for decryption benchmark: %v", err)
					os.Remove(testFile)
					continue
				}
				decResult := qe.benchmarkOperation("decrypt", encryptedFile, keyBaseName+KeyExt, fileSize)
				fmt.Printf("Stream decryption...")
				if decResult.Success {
					fmt.Printf(" ✓ %.2f MB/s\n", decResult.Throughput)
				} else {
					fmt.Printf(" ✗ %s\n", decResult.Error)
				}
				if config.CleanupFiles {
					os.Remove(testFile)
					os.Remove(encryptedFile)
				}
			}
		}
	}
	fmt.Printf("\n✅ **Streaming Encryption Test Completed!**\n")
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
		fmt.Println("Post-Quantum Secure Stream Encryption Engine (v3)")
		flag.PrintDefaults()
		return
	}
	var level SecurityLevel
	switch *securityLevel {
	case "128":
		level = Level128
		*useMLKEM = false
	case "192":
		level = Level192
	case "256":
		level = Level256
	default:
		log.Fatalf("Invalid security level: %s (use 128, 192, or 256)", *securityLevel)
	}
	if *useMLKEM && level == Level128 {
		log.Printf("Warning: ML-KEM-512 not supported, falling back to Kyber512")
		*useMLKEM = false
	}
	engine := NewQuantumEngine(level, *useMLKEM)
	switch {
	case *benchmark:
		config := StressTestConfig{
			FileSizes:      []int64{10 * 1024, 1024 * 1024, 100 * 1024 * 1024, 1 * 1024 * 1024 * 1024}, // 10KB, 1MB, 100MB, 1GB
			Concurrency:    runtime.NumCPU(),
			CleanupFiles:   true,
			SecurityLevels: []SecurityLevel{Level192, Level256},
		}
		engine.runStressTest(config)
	case *generateKeys:
		keyPair, err := engine.GenerateHybridKeyPair()
		if err != nil {
			log.Fatalf("Key generation failed: %v", err)
		}
		if err := engine.SaveHybridKeys(keyPair, *keyName); err != nil {
			log.Fatalf("Failed to save keys: %v", err)
		}
	case *encrypt != "":
		if *publicKey == "" {
			*publicKey = *keyName + PubKeyExt
		}
		outputFile := *output
		if outputFile == "" {
			outputFile = *encrypt + EncryptedExt
		}
		fmt.Printf("Encrypting %s -> %s ...\n", *encrypt, outputFile)
		if err := engine.EncryptFile(*encrypt, outputFile, *publicKey); err != nil {
			log.Fatalf("Encryption failed: %v", err)
		}
		fmt.Println("Encryption successful.")
	case *decrypt != "":
		if *privateKey == "" {
			*privateKey = *keyName + KeyExt
		}
		outputFile := *output
		if outputFile == "" {
			ext := filepath.Ext(*decrypt)
			if ext == EncryptedExt {
				outputFile = (*decrypt)[:len(*decrypt)-len(ext)]
			} else {
				outputFile = *decrypt + ".decrypted"
			}
		}
		fmt.Printf("Decrypting %s -> %s ...\n", *decrypt, outputFile)
		if err := engine.DecryptFile(*decrypt, outputFile, *privateKey); err != nil {
			log.Fatalf("Decryption failed: %v", err)
		}
		fmt.Println("Decryption and integrity verification successful.")
	default:
		fmt.Println("Use -help for usage information.")
	}
}
