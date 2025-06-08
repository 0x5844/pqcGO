package main

import (
	"bytes"
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
	"sync"
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
	ChaChaNonceSize        = 24
	ChaChaBlockSize        = 64
	X25519KeySize          = 32
	X25519SharedSecretSize = 32
	Blake2sHashSize        = 32
	HmacInfoSize           = 32
	StreamChunkSize        = 1 * 1024 * 1024
	KeyExt                 = ".key"
	PubKeyExt              = ".pub"
	EncryptedExt           = ".enc"
	FileFormatVersion      = 3
	DerivationContextSize  = 32
)

var (
	numWorkers = runtime.NumCPU()
	bufferPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, StreamChunkSize)
			return &b
		},
	}
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

func getKyberParams(level SecurityLevel) *kyber.Kyber {
	switch level {
	case Level128:
		return kyber.NewKyber512()
	case Level192:
		return kyber.NewKyber768()
	case Level256:
		return kyber.NewKyber1024()
	default:
		return kyber.NewKyber768()
	}
}

type HybridKeyPair struct {
	MLKEMPublicKey   []byte
	MLKEMPrivateKey  []byte
	X25519PublicKey  [X25519KeySize]byte
	X25519PrivateKey [X25519KeySize]byte
	KyberPublicKey   []byte
	KyberPrivateKey  []byte
	SecurityLevel    SecurityLevel
	UseMLKEM         bool
}

type QuantumEngine struct {
	securityLevel SecurityLevel
	useMLKEM      bool
}

type EncryptedHeader struct {
	Version           uint32
	SecurityLevel     uint32
	UseMLKEM          bool
	MLKEMCiphertext   []byte
	X25519PublicKey   []byte
	KyberCiphertext   []byte
	Nonce             []byte
	DerivationContext []byte
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

type chunkJob struct {
	id   int
	data []byte
}

type chunkResult struct {
	id   int
	data []byte
	err  error
}

func generateSecureRandomString(length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("invalid length: %d", length)
	}

	randomBytes := make([]byte, length)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("failed to generate secure random bytes: %w", err)
	}

	return randomBytes, nil
}

func NewQuantumEngine(level SecurityLevel, preferMLKEM bool) *QuantumEngine {
	return &QuantumEngine{
		securityLevel: level,
		useMLKEM:      preferMLKEM,
	}
}

func deriveKeyBLAKE2s(sharedSecret []byte, info []byte) ([]byte, error) {
	h, err := blake2s.New256(nil)
	if err != nil {
		return nil, err
	}
	h.Write(sharedSecret)
	h.Write(info)
	return h.Sum(nil), nil
}

func deriveHybridKey(mlkemSecret, x25519Secret, kyberSecret []byte, derivationContext []byte) ([]byte, error) {
	h := hkdf.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, append(append(mlkemSecret, x25519Secret...), kyberSecret...), nil, derivationContext)
	key := make([]byte, ChaChaKeySize)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, err
	}
	return key, nil
}

func (qe *QuantumEngine) GenerateHybridKeyPair() (*HybridKeyPair, error) {
	keyPair := &HybridKeyPair{
		SecurityLevel: qe.securityLevel,
		UseMLKEM:      qe.useMLKEM,
	}

	x25519Private := make([]byte, X25519KeySize)
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

	kyberParams := getKyberParams(qe.securityLevel)
	kyberPublic, kyberPrivate := kyberParams.KeyGen(nil)
	if kyberPublic == nil || kyberPrivate == nil {
		return nil, fmt.Errorf("failed to generate Kyber fallback keys")
	}
	keyPair.KyberPublicKey = kyberPublic
	keyPair.KyberPrivateKey = kyberPrivate
	return keyPair, nil
}

func writeBytesWithLength(w io.Writer, data []byte) error {
	if err := binary.Write(w, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func readBytesWithLength(r io.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (qe *QuantumEngine) SaveHybridKeys(keyPair *HybridKeyPair, baseName string) error {
	privateKeyFile := baseName + KeyExt
	privFile, err := os.OpenFile(privateKeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer privFile.Close()

	binary.Write(privFile, binary.BigEndian, uint32(FileFormatVersion))
	binary.Write(privFile, binary.BigEndian, uint32(keyPair.SecurityLevel))
	binary.Write(privFile, binary.BigEndian, keyPair.UseMLKEM)
	privFile.Write(keyPair.X25519PrivateKey[:])
	writeBytesWithLength(privFile, keyPair.MLKEMPrivateKey)
	writeBytesWithLength(privFile, keyPair.KyberPrivateKey)

	publicKeyFile := baseName + PubKeyExt
	pubFile, err := os.Create(publicKeyFile)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer pubFile.Close()

	binary.Write(pubFile, binary.BigEndian, uint32(FileFormatVersion))
	binary.Write(pubFile, binary.BigEndian, uint32(keyPair.SecurityLevel))
	binary.Write(pubFile, binary.BigEndian, keyPair.UseMLKEM)
	pubFile.Write(keyPair.X25519PublicKey[:])
	writeBytesWithLength(pubFile, keyPair.MLKEMPublicKey)
	writeBytesWithLength(pubFile, keyPair.KyberPublicKey)

	fmt.Printf("Hybrid keys saved:\n")
	fmt.Printf("  Private: %s\n", privateKeyFile)
	fmt.Printf("  Public: %s\n", publicKeyFile)
	algo := "Kyber"
	if keyPair.UseMLKEM {
		algo = "ML-KEM"
	}
	fmt.Printf("  Security: %s (%s)\n", keyPair.SecurityLevel.String(), algo)
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
	var useMLKEM bool
	binary.Read(file, binary.BigEndian, &version)
	binary.Read(file, binary.BigEndian, &secLevel)
	binary.Read(file, binary.BigEndian, &useMLKEM)
	keyPair.SecurityLevel = SecurityLevel(secLevel)
	keyPair.UseMLKEM = useMLKEM

	io.ReadFull(file, keyPair.X25519PublicKey[:])
	keyPair.MLKEMPublicKey, err = readBytesWithLength(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read ML-KEM public key: %w", err)
	}
	keyPair.KyberPublicKey, err = readBytesWithLength(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read Kyber public key: %w", err)
	}
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
	var useMLKEM bool
	binary.Read(file, binary.BigEndian, &version)
	binary.Read(file, binary.BigEndian, &secLevel)
	binary.Read(file, binary.BigEndian, &useMLKEM)
	keyPair.SecurityLevel = SecurityLevel(secLevel)
	keyPair.UseMLKEM = useMLKEM

	io.ReadFull(file, keyPair.X25519PrivateKey[:])
	var keyErr error
	keyPair.MLKEMPrivateKey, keyErr = readBytesWithLength(file)
	if keyErr != nil {
		return nil, fmt.Errorf("failed to read ML-KEM private key: %w", keyErr)
	}
	keyPair.KyberPrivateKey, keyErr = readBytesWithLength(file)
	if keyErr != nil {
		return nil, fmt.Errorf("failed to read Kyber private key: %w", keyErr)
	}
	return keyPair, nil
}

func (qe *QuantumEngine) HybridEncapsulate(publicKeyPair *HybridKeyPair) (*EncryptedHeader, []byte, error) {
	header := &EncryptedHeader{
		Version:       FileFormatVersion,
		SecurityLevel: uint32(publicKeyPair.SecurityLevel),
		UseMLKEM:      publicKeyPair.UseMLKEM,
	}

	derivationContext, err := generateSecureRandomString(DerivationContextSize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate derivation context: %w", err)
	}
	header.DerivationContext = derivationContext

	var mlkemSecret, x25519Secret, kyberSecret []byte

	if publicKeyPair.UseMLKEM && len(publicKeyPair.MLKEMPublicKey) > 0 {
		switch publicKeyPair.SecurityLevel {
		case Level192:
			ek, err := mlkem.NewEncapsulationKey768(publicKeyPair.MLKEMPublicKey)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create ML-KEM-768 encapsulation key: %w", err)
			}
			secret, ciphertext := ek.Encapsulate()
			mlkemSecret, header.MLKEMCiphertext = secret, ciphertext
		case Level256:
			ek, err := mlkem.NewEncapsulationKey1024(publicKeyPair.MLKEMPublicKey)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create ML-KEM-1024 encapsulation key: %w", err)
			}
			secret, ciphertext := ek.Encapsulate()
			mlkemSecret, header.MLKEMCiphertext = secret, ciphertext
		}
	}

	x25519EphemeralPrivate := make([]byte, X25519KeySize)
	if _, err := rand.Read(x25519EphemeralPrivate); err != nil {
		return nil, nil, fmt.Errorf("failed to generate X25519 ephemeral key: %w", err)
	}
	header.X25519PublicKey, err = curve25519.X25519(x25519EphemeralPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate X25519 ephemeral public key: %w", err)
	}
	x25519Secret, err = curve25519.X25519(x25519EphemeralPrivate, publicKeyPair.X25519PublicKey[:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to perform X25519 key exchange: %w", err)
	}

	kyberParams := getKyberParams(publicKeyPair.SecurityLevel)
	kyberCiphertext, kyberSharedSecret := kyberParams.Encaps(publicKeyPair.KyberPublicKey, nil)
	if kyberCiphertext == nil || kyberSharedSecret == nil {
		return nil, nil, fmt.Errorf("failed to encapsulate Kyber shared secret")
	}
	kyberSecret, header.KyberCiphertext = kyberSharedSecret, kyberCiphertext

	encryptionKey, err := deriveHybridKey(mlkemSecret, x25519Secret, kyberSecret, derivationContext)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive hybrid encryption key: %w", err)
	}

	return header, encryptionKey, nil
}

func (qe *QuantumEngine) HybridDecapsulate(privateKeyPair *HybridKeyPair, header *EncryptedHeader) ([]byte, error) {
	var mlkemSecret, x25519Secret, kyberSecret []byte
	var err error

	if header.UseMLKEM && len(header.MLKEMCiphertext) > 0 {
		switch SecurityLevel(header.SecurityLevel) {
		case Level192:
			dk, err := mlkem.NewDecapsulationKey768(privateKeyPair.MLKEMPrivateKey)
			if err != nil {
				return nil, fmt.Errorf("failed to create ML-KEM-768 decapsulation key: %w", err)
			}
			mlkemSecret, err = dk.Decapsulate(header.MLKEMCiphertext)
			if err != nil {
				return nil, fmt.Errorf("failed to decapsulate ML-KEM-768: %w", err)
			}
		case Level256:
			dk, err := mlkem.NewDecapsulationKey1024(privateKeyPair.MLKEMPrivateKey)
			if err != nil {
				return nil, fmt.Errorf("failed to create ML-KEM-1024 decapsulation key: %w", err)
			}
			mlkemSecret, err = dk.Decapsulate(header.MLKEMCiphertext)
			if err != nil {
				return nil, fmt.Errorf("failed to decapsulate ML-KEM-1024: %w", err)
			}
		}
	}

	x25519Secret, err = curve25519.X25519(privateKeyPair.X25519PrivateKey[:], header.X25519PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to perform X25519 key exchange: %w", err)
	}

	kyberParams := getKyberParams(privateKeyPair.SecurityLevel)
	kyberSecret = kyberParams.Decaps(privateKeyPair.KyberPrivateKey, header.KyberCiphertext)
	if kyberSecret == nil {
		return nil, fmt.Errorf("failed to decapsulate Kyber shared secret")
	}

	return deriveHybridKey(mlkemSecret, x25519Secret, kyberSecret, header.DerivationContext)
}

func (qe *QuantumEngine) saveEncryptedHeader(w io.Writer, header *EncryptedHeader) error {
	binary.Write(w, binary.BigEndian, header.Version)
	binary.Write(w, binary.BigEndian, header.SecurityLevel)
	binary.Write(w, binary.BigEndian, header.UseMLKEM)
	if err := writeBytesWithLength(w, header.MLKEMCiphertext); err != nil {
		return err
	}
	if err := writeBytesWithLength(w, header.X25519PublicKey); err != nil {
		return err
	}
	if err := writeBytesWithLength(w, header.KyberCiphertext); err != nil {
		return err
	}
	if err := writeBytesWithLength(w, header.Nonce); err != nil {
		return err
	}
	// Save the derivation context
	return writeBytesWithLength(w, header.DerivationContext)
}

func (qe *QuantumEngine) loadEncryptedHeader(r io.Reader) (*EncryptedHeader, int64, error) {
	header := &EncryptedHeader{}
	startCounter := &byteCounter{r: r}
	var err error

	binary.Read(startCounter, binary.BigEndian, &header.Version)
	binary.Read(startCounter, binary.BigEndian, &header.SecurityLevel)
	binary.Read(startCounter, binary.BigEndian, &header.UseMLKEM)

	if header.MLKEMCiphertext, err = readBytesWithLength(startCounter); err != nil {
		return nil, 0, err
	}
	if header.X25519PublicKey, err = readBytesWithLength(startCounter); err != nil {
		return nil, 0, err
	}
	if header.KyberCiphertext, err = readBytesWithLength(startCounter); err != nil {
		return nil, 0, err
	}
	if header.Nonce, err = readBytesWithLength(startCounter); err != nil {
		return nil, 0, err
	}
	if header.DerivationContext, err = readBytesWithLength(startCounter); err != nil {
		return nil, 0, err
	}
	return header, startCounter.bytes, nil
}

type byteCounter struct {
	r     io.Reader
	bytes int64
}

func (bc *byteCounter) Read(p []byte) (n int, err error) {
	n, err = bc.r.Read(p)
	bc.bytes += int64(n)
	return
}

func (qe *QuantumEngine) processStream(r io.Reader, w io.Writer, key, nonce []byte) error {
	jobs := make(chan chunkJob, numWorkers)
	results := make(chan chunkResult, numWorkers)
	var wg sync.WaitGroup
	var processorErr error
	var once sync.Once

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			streamCipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
			if err != nil {
				once.Do(func() { processorErr = err })
				return
			}
			for job := range jobs {
				blockOffset := uint64(job.id) * uint64(StreamChunkSize) / ChaChaBlockSize
				streamCipher.SetCounter(uint32(blockOffset))
				processedData := make([]byte, len(job.data))
				streamCipher.XORKeyStream(processedData, job.data)
				bufferPool.Put(&job.data)
				results <- chunkResult{id: job.id, data: processedData}
			}
		}()
	}

	var writeErr error
	var writeWg sync.WaitGroup
	writeWg.Add(1)
	go func() {
		defer writeWg.Done()
		resultMap := make(map[int][]byte)
		nextID := 0
		for result := range results {
			if result.err != nil {
				writeErr = result.err
				break
			}
			resultMap[result.id] = result.data
			for {
				data, ok := resultMap[nextID]
				if !ok {
					break
				}
				if _, err := w.Write(data); err != nil {
					writeErr = fmt.Errorf("failed to write processed chunk %d: %w", nextID, err)
					delete(resultMap, nextID)
					break
				}
				delete(resultMap, nextID)
				nextID++
			}
			if writeErr != nil {
				break
			}
		}
	}()

	chunkID := 0
	for {
		bufferPtr := bufferPool.Get().(*[]byte)
		n, err := r.Read(*bufferPtr)
		if n > 0 {
			jobs <- chunkJob{id: chunkID, data: (*bufferPtr)[:n]}
			chunkID++
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			close(jobs)
			wg.Wait()
			close(results)
			writeWg.Wait()
			return fmt.Errorf("failed to read from input stream: %w", err)
		}
	}

	close(jobs)
	wg.Wait()
	close(results)
	writeWg.Wait()

	if processorErr != nil {
		return fmt.Errorf("worker initialization failed: %w", processorErr)
	}
	return writeErr
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

	header, encryptionKey, err := qe.HybridEncapsulate(publicKeyPair)
	if err != nil {
		return err
	}
	nonce := make([]byte, ChaChaNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}
	header.Nonce = nonce

	hmacInfo := make([]byte, HmacInfoSize)
	if _, err := io.ReadFull(rand.Reader, hmacInfo); err != nil {
		return fmt.Errorf("failed to generate HMAC info: %w", err)
	}
	hmacKey, err := deriveKeyBLAKE2s(encryptionKey, hmacInfo)
	if err != nil {
		return fmt.Errorf("failed to derive HMAC key: %w", err)
	}

	headerBuf := new(bytes.Buffer)
	if err := qe.saveEncryptedHeader(headerBuf, header); err != nil {
		return fmt.Errorf("failed to serialize header: %w", err)
	}

	mac := hmac.New(func() hash.Hash { h, _ := blake2s.New256(nil); return h }, hmacKey)
	macWriter := io.MultiWriter(outFile, mac)

	if _, err := macWriter.Write(headerBuf.Bytes()); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	if err := qe.processStream(inFile, macWriter, encryptionKey, nonce); err != nil {
		return fmt.Errorf("stream processing failed during encryption: %w", err)
	}

	if _, err := outFile.Write(mac.Sum(nil)); err != nil {
		return fmt.Errorf("failed to write HMAC: %w", err)
	}
	if _, err := outFile.Write(hmacInfo); err != nil {
		return fmt.Errorf("failed to write HMAC info: %w", err)
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
	if fileSize < (Blake2sHashSize + HmacInfoSize) {
		return fmt.Errorf("input file is too small to be valid")
	}

	hmacInfo := make([]byte, HmacInfoSize)
	if _, err := inFile.ReadAt(hmacInfo, fileSize-HmacInfoSize); err != nil {
		return fmt.Errorf("failed to read HMAC info: %w", err)
	}
	expectedHMAC := make([]byte, Blake2sHashSize)
	if _, err := inFile.ReadAt(expectedHMAC, fileSize-Blake2sHashSize-HmacInfoSize); err != nil {
		return fmt.Errorf("failed to read expected HMAC: %w", err)
	}

	if _, err := inFile.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to start of input file: %w", err)
	}

	header, headerSize, err := qe.loadEncryptedHeader(inFile)
	if err != nil {
		return fmt.Errorf("failed to load encrypted header: %w", err)
	}

	encryptionKey, err := qe.HybridDecapsulate(privateKeyPair, header)
	if err != nil {
		return err
	}
	hmacKey, err := deriveKeyBLAKE2s(encryptionKey, hmacInfo)
	if err != nil {
		return fmt.Errorf("failed to derive HMAC key: %w", err)
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

	mac := hmac.New(func() hash.Hash { h, _ := blake2s.New256(nil); return h }, hmacKey)
	if _, err := inFile.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek for verification: %w", err)
	}
	if _, err := io.CopyN(mac, inFile, headerSize); err != nil {
		return fmt.Errorf("failed to hash header for verification: %w", err)
	}

	contentLength := fileSize - headerSize - Blake2sHashSize - HmacInfoSize
	verifyingReader := io.TeeReader(io.LimitReader(inFile, contentLength), mac)

	err = qe.processStream(verifyingReader, outTmpFile, encryptionKey, header.Nonce)
	if err != nil {
		return err
	}

	computedHMAC := mac.Sum(nil)
	if !hmac.Equal(computedHMAC, expectedHMAC) {
		return fmt.Errorf("file integrity verification failed: HMAC mismatch")
	}

	if err := outTmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %w", err)
	}
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

				encResult := engine.benchmarkOperation("encrypt", testFile, keyBaseName+PubKeyExt, fileSize)
				fmt.Printf("Stream encryption...")
				if encResult.Success {
					fmt.Printf(" ✓ %.2f MB/s\n", encResult.Throughput)
				} else {
					fmt.Printf(" ✗ %s\n", encResult.Error)
					os.Remove(testFile)
					continue
				}

				if err := engine.EncryptFile(testFile, encryptedFile, keyBaseName+PubKeyExt); err != nil {
					log.Printf("FAIL: Could not create file for decryption benchmark: %v", err)
					os.Remove(testFile)
					continue
				}

				decResult := engine.benchmarkOperation("decrypt", encryptedFile, keyBaseName+KeyExt, fileSize)
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
		useMLKEM      = flag.Bool("mlkem", true, "Use Go 1.24+ ML-KEM (vs legacy Kyber)")
		help          = flag.Bool("help", false, "Show help message")
	)
	flag.Parse()

	if *help || (len(os.Args) == 1 && !*benchmark) {
		fmt.Println("Post-Quantum Secure Stream Encryption Engine (v3.3-revised)")
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
			FileSizes:      []int64{10 * 1024, 1024 * 1024, 100 * 1024 * 1024, 1 * 1024 * 1024 * 1024},
			Concurrency:    numWorkers,
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
		fmt.Printf("Encrypting %s -> %s using %d worker(s)...\n", *encrypt, outputFile, numWorkers)
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
		fmt.Printf("Decrypting %s -> %s using %d worker(s)...\n", *decrypt, outputFile, numWorkers)
		if err := engine.DecryptFile(*decrypt, outputFile, *privateKey); err != nil {
			log.Fatalf("Decryption failed: %v", err)
		}
		fmt.Println("Decryption and integrity verification successful.")

	default:
		fmt.Println("No action specified. Use -help for usage information.")
	}
}
