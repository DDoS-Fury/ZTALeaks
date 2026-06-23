package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidHash         = errors.New("il formato dell'hash non e corretto")
	ErrIncompatibleVersion = errors.New("versione di argon2 non compatibile")
)

type params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

var p = &params{
	memory:      64 * 1024,
	iterations:  3,
	parallelism: 4,
	saltLength:  16,
	keyLength:   32,
}

// GenerateFromPassword crea un hash Argon2id (Standard MCF) per la password fornita.
func GenerateFromPassword(password string) (string, error) {
	salt := make([]byte, p.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Struttura standard: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.memory, p.iterations, p.parallelism, b64Salt, b64Hash)

	return encodedHash, nil
}

// ComparePasswordAndHash verifica se una password corrisponde all'hash memorizzato.
func ComparePasswordAndHash(password, encodedHash string) (bool, error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 || vals[1] != "argon2id" {
		return false, ErrInvalidHash
	}

	var version int
	_, err := fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return false, err
	}
	if version != argon2.Version {
		return false, ErrIncompatibleVersion
	}

	decodeParams := &params{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d",
		&decodeParams.memory, &decodeParams.iterations, &decodeParams.parallelism)
	if err != nil {
		return false, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(vals[4])
	if err != nil {
		return false, err
	}
	decodeParams.saltLength = uint32(len(salt))

	hash, err := base64.RawStdEncoding.DecodeString(vals[5])
	if err != nil {
		return false, err
	}
	decodeParams.keyLength = uint32(len(hash))

	comparisonHash := argon2.IDKey([]byte(password), salt, decodeParams.iterations, decodeParams.memory, decodeParams.parallelism, decodeParams.keyLength)

	// subtle.ConstantTimeCompare è fondamentale per mitigare gli attacchi basati sui tempi di esecuzione (timing attack)
	if subtle.ConstantTimeCompare(hash, comparisonHash) == 1 {
		return true, nil
	}
	return false, nil
}
