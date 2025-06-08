package main

import (
	"bytes"
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
	"sync/atomic"
	"time"

	"crypto/mlkem"

	kyber "github.com/kudelskisecurity/crystals-go/crystals-kyber"
	"github.com/pierrec/lz4/v4"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	AEADKeySize           = 32
	XChaCha20NonceSize    = 24
	X25519KeySize         = 32
	StreamChunkSize       = 1 * 1024 * 1024
	KeyExt                = ".key"
	PubKeyExt             = ".pub"
	EncryptedExt          = ".enc"
	FileFormatVersion     = 5
	DerivationContextSize = 32
	AEADOverhead          = 16
)

var (
	numWorkers   = runtime.NumCPU()
	nonceCounter uint64
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

func (k *HybridKeyPair) Zeroize() {
	for i := range k.X25519PrivateKey {
		k.X25519PrivateKey[i] = 0
	}
	for i := range k.MLKEMPrivateKey {
		k.MLKEMPrivateKey[i] = 0
	}
	for i := range k.KyberPrivateKey {
		k.KyberPrivateKey[i] = 0
	}
}

type QuantumEngine struct {
	securityLevel    SecurityLevel
	useMLKEM         bool
	compressionLevel int
}

type EncryptedHeader struct {
	Version           uint32
	SecurityLevel     uint32
	UseMLKEM          bool
	CompressionLevel  int32
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
	FileSizes        []int64
	Iterations       int
	Concurrency      int
	CleanupFiles     bool
	SecurityLevels   []SecurityLevel
	CompressionLevel int
}

type chunkJob struct {
	id      int
	data    []byte
	encrypt bool
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

func NewQuantumEngine(level SecurityLevel, preferMLKEM bool, compressionLevel int) *QuantumEngine {
	return &QuantumEngine{
		securityLevel:    level,
		useMLKEM:         preferMLKEM,
		compressionLevel: compressionLevel,
	}
}

func deriveHybridKeySecure(mlkemSecret, x25519Secret, kyberSecret []byte, mlkemCt, x25519Ct, kyberCt []byte, derivationContext []byte) ([]byte, error) {
	combinedSecrets := append(append(mlkemSecret, x25519Secret...), kyberSecret...)
	combinedCt := append(append(mlkemCt, x25519Ct...), kyberCt...)
	info := append(combinedCt, derivationContext...)

	h := hkdf.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, combinedSecrets, nil, info)

	key := make([]byte, AEADKeySize)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, err
	}
	return key, nil
}

func atomicNonce() []byte {
	count := atomic.AddUint64(&nonceCounter, 1)
	nonce := make([]byte, XChaCha20NonceSize)
	binary.BigEndian.PutUint64(nonce[16:], count)
	return nonce
}

func createChunkNonce(baseNonce []byte, chunkID int) []byte {
	if len(baseNonce) != XChaCha20NonceSize {
		panic("invalid base nonce size")
	}
	nonce := make([]byte, XChaCha20NonceSize)
	copy(nonce, baseNonce)
	binary.BigEndian.PutUint64(nonce[16:], uint64(chunkID))
	return nonce
}

func (qe *QuantumEngine) encryptChunkAEAD(data, key, baseNonce []byte, chunkID int) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305 cipher: %w", err)
	}
	chunkNonce := createChunkNonce(baseNonce, chunkID)
	aad := make([]byte, 8)
	binary.BigEndian.PutUint64(aad, uint64(chunkID))
	return aead.Seal(nil, chunkNonce, data, aad), nil
}

func (qe *QuantumEngine) decryptChunkAEAD(ciphertext, key, baseNonce []byte, chunkID int) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305 cipher: %w", err)
	}
	chunkNonce := createChunkNonce(baseNonce, chunkID)
	aad := make([]byte, 8)
	binary.BigEndian.PutUint64(aad, uint64(chunkID))
	plaintext, err := aead.Open(nil, chunkNonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("chunk %d authentication failed: %w", chunkID, err)
	}
	return plaintext, nil
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
	defer keyPair.Zeroize()
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
		Version:          FileFormatVersion,
		SecurityLevel:    uint32(publicKeyPair.SecurityLevel),
		UseMLKEM:         publicKeyPair.UseMLKEM,
		CompressionLevel: int32(qe.compressionLevel),
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
	encryptionKey, err := deriveHybridKeySecure(mlkemSecret, x25519Secret, kyberSecret, header.MLKEMCiphertext, header.X25519PublicKey, header.KyberCiphertext, derivationContext)
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
	return deriveHybridKeySecure(mlkemSecret, x25519Secret, kyberSecret, header.MLKEMCiphertext, header.X25519PublicKey, header.KyberCiphertext, header.DerivationContext)
}

func (qe *QuantumEngine) saveEncryptedHeader(w io.Writer, header *EncryptedHeader) error {
	binary.Write(w, binary.BigEndian, header.Version)
	binary.Write(w, binary.BigEndian, header.SecurityLevel)
	binary.Write(w, binary.BigEndian, header.UseMLKEM)
	binary.Write(w, binary.BigEndian, header.CompressionLevel)
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
	return writeBytesWithLength(w, header.DerivationContext)
}

func (qe *QuantumEngine) loadEncryptedHeader(r io.Reader) (*EncryptedHeader, int64, error) {
	header := &EncryptedHeader{}
	startCounter := &byteCounter{r: r}
	var err error
	binary.Read(startCounter, binary.BigEndian, &header.Version)
	binary.Read(startCounter, binary.BigEndian, &header.SecurityLevel)
	binary.Read(startCounter, binary.BigEndian, &header.UseMLKEM)
	binary.Read(startCounter, binary.BigEndian, &header.CompressionLevel)
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

func (qe *QuantumEngine) processStream(r io.Reader, w io.Writer, key, nonce []byte, encrypt bool) error {
	jobs := make(chan chunkJob, numWorkers*4)
	results := make(chan chunkResult, numWorkers*4)
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				var processedData []byte
				var err error
				if job.encrypt {
					processedData, err = qe.encryptChunkAEAD(job.data, key, nonce, job.id)
				} else {
					processedData, err = qe.decryptChunkAEAD(job.data, key, nonce, job.id)
				}
				results <- chunkResult{id: job.id, data: processedData, err: err}
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
				return
			}
			resultMap[result.id] = result.data
			for {
				data, ok := resultMap[nextID]
				if !ok {
					break
				}
				if _, err := w.Write(data); err != nil {
					writeErr = fmt.Errorf("failed to write processed chunk %d: %w", nextID, err)
					return
				}
				delete(resultMap, nextID)
				nextID++
			}
		}
	}()

	chunkID := 0
	readSize := StreamChunkSize
	if !encrypt {
		readSize += AEADOverhead
	}
	for {
		buffer := make([]byte, readSize)
		n, err := io.ReadFull(r, buffer)
		if n > 0 {
			jobData := make([]byte, n)
			copy(jobData, buffer[:n])
			jobs <- chunkJob{id: chunkID, data: jobData, encrypt: encrypt}
			chunkID++
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			writeErr = fmt.Errorf("failed to read from input stream: %w", err)
			break
		}
		if writeErr != nil {
			break
		}
	}

	close(jobs)
	wg.Wait()
	close(results)
	writeWg.Wait()
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
	nonce := atomicNonce()
	header.Nonce = nonce
	headerBuf := new(bytes.Buffer)
	if err := qe.saveEncryptedHeader(headerBuf, header); err != nil {
		return fmt.Errorf("failed to serialize header: %w", err)
	}
	if _, err := outFile.Write(headerBuf.Bytes()); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	if qe.compressionLevel < 0 {
		return qe.processStream(inFile, outFile, encryptionKey, nonce, true)
	}

	pr, pw := io.Pipe()
	errChan := make(chan error, 1)

	go func() {
		defer pw.Close()
		lz4Writer := lz4.NewWriter(pw)
		if err := lz4Writer.Apply(lz4.CompressionLevelOption(qe.getCompressionLevelOption(qe.compressionLevel))); err != nil {
			errChan <- fmt.Errorf("failed to set compression level: %w", err)
			return
		}
		if _, err := io.Copy(lz4Writer, inFile); err != nil {
			errChan <- fmt.Errorf("compression failed: %w", err)
			return
		}
		if err := lz4Writer.Close(); err != nil {
			errChan <- fmt.Errorf("failed to close lz4 writer: %w", err)
			return
		}
		errChan <- nil
	}()

	streamErr := qe.processStream(pr, outFile, encryptionKey, nonce, true)
	compressErr := <-errChan

	if streamErr != nil {
		return fmt.Errorf("encryption stream failed: %w", streamErr)
	}
	if compressErr != nil {
		return fmt.Errorf("compression stage failed: %w", compressErr)
	}

	return nil
}

func (qe *QuantumEngine) getCompressionLevelOption(level int) lz4.CompressionLevel {
	switch level {
	case 0:
		return lz4.Fast
	case 1:
		return lz4.Level1
	case 2:
		return lz4.Level2
	case 3:
		return lz4.Level3
	case 4:
		return lz4.Level4
	case 5:
		return lz4.Level5
	case 6:
		return lz4.Level6
	case 7:
		return lz4.Level7
	case 8:
		return lz4.Level8
	case 9:
		return lz4.Level9
	default:
		return lz4.Fast
	}
}

func (qe *QuantumEngine) DecryptFile(inputFile, outputFile, privateKeyFile string) (err error) {
	privateKeyPair, err := qe.LoadHybridPrivateKey(privateKeyFile)
	if err != nil {
		return err
	}
	defer privateKeyPair.Zeroize()
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inFile.Close()
	header, headerSize, err := qe.loadEncryptedHeader(inFile)
	if err != nil {
		return fmt.Errorf("failed to load encrypted header: %w", err)
	}
	encryptionKey, err := qe.HybridDecapsulate(privateKeyPair, header)
	if err != nil {
		return err
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
	if _, err := inFile.Seek(headerSize, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to content start: %w", err)
	}

	if header.CompressionLevel < 0 {
		if err := qe.processStream(inFile, outTmpFile, encryptionKey, header.Nonce, false); err != nil {
			return err
		}
	} else {
		pr, pw := io.Pipe()
		errChan := make(chan error, 1)

		go func() {
			defer pw.Close()
			err := qe.processStream(inFile, pw, encryptionKey, header.Nonce, false)
			errChan <- err
		}()

		lz4Reader := lz4.NewReader(pr)
		_, copyErr := io.Copy(outTmpFile, lz4Reader)

		streamErr := <-errChan
		if streamErr != nil {
			return fmt.Errorf("decryption stream failed: %w", streamErr)
		}
		if copyErr != nil {
			return fmt.Errorf("decompression failed: %w", copyErr)
		}
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
		Algorithm:     fmt.Sprintf("Hybrid %s+X25519+XChaCha20-Poly1305", algorithm),
	}
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

func (qe *QuantumEngine) runStressTest(config StressTestConfig) {
	fmt.Printf("\n🚀 **Post-Quantum Stream Encryption Stress Test**\n")
	fmt.Printf("==================================================\n")
	fmt.Printf("Hybrid KEM: ML-KEM/Kyber + X25519 | Stream Cipher: XChaCha20-Poly1305 AEAD\n")
	fmt.Printf("Hash: BLAKE2s | Integrity: Built-in Poly1305 Authentication\n")
	fmt.Printf("Concurrency: %d threads | CPU Cores: %d | Go Version: %s | Compression Level: %d\n", config.Concurrency, runtime.NumCPU(), runtime.Version(), config.CompressionLevel)
	for _, secLevel := range config.SecurityLevels {
		for _, useMLKEM := range []bool{true, false} {
			if useMLKEM && secLevel == Level128 {
				continue
			}
			engine := NewQuantumEngine(secLevel, useMLKEM, qe.compressionLevel)
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
				fmt.Printf("AEAD encryption...")
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
				fmt.Printf("AEAD decryption...")
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
	fmt.Printf("\n✅ **XChaCha20-Poly1305 AEAD Test Completed!**\n")
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
		compressLevel = flag.Int("compress-level", 4, "LZ4 compression level (0=fastest, 9=best). Use -1 to disable.")
		help          = flag.Bool("help", false, "Show help message")
	)
	flag.Parse()
	if *help || (len(os.Args) == 1 && !*benchmark) {
		fmt.Println("Post-Quantum Secure Stream Encryption Engine (v4.0-AEAD)")
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
	if *compressLevel > 9 {
		*compressLevel = 9
	}

	engine := NewQuantumEngine(level, *useMLKEM, *compressLevel)
	switch {
	case *benchmark:
		config := StressTestConfig{
			FileSizes:        []int64{10 * 1024, 1024 * 1024, 100 * 1024 * 1024, 1 * 1024 * 1024 * 1024},
			Concurrency:      numWorkers,
			CleanupFiles:     true,
			SecurityLevels:   []SecurityLevel{Level192, Level256},
			CompressionLevel: *compressLevel,
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
		fmt.Println("XChaCha20-Poly1305 AEAD encryption successful.")
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
		fmt.Println("XChaCha20-Poly1305 AEAD decryption and integrity verification successful.")
	default:
		fmt.Println("No action specified. Use -help for usage information.")
	}
}
