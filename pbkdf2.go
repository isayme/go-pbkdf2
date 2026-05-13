package pbkdf2

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// Package pbkdf2 provides PBKDF2 password hashing and verification.
// It uses SHA-256 as the hash function.

// Params defines the PBKDF2 algorithm parameters.
type Params struct {
	// Iterations is the number of iterations.
	Iterations int
	// Digest is the hash function to use. Supported values: sha1, sha256, sha512.
	Digest string

	// SaltLen is the length of the salt.
	SaltLen int
	// KeyLen is the length of the derived key.
	KeyLen int
}

// DefaultParams returns the recommended default PBKDF2 parameters.
// Iterations=100000, KeyLen=32
var DefaultParams = Params{
	Iterations: 100000,
	Digest:     "sha256",
	KeyLen:     32,
	SaltLen:    16,
}

func randomBytes(len int) ([]byte, error) {
	buf := make([]byte, len)
	_, err := rand.Read(buf)
	return buf, err
}

func getHash(digest string) func() hash.Hash {
	switch digest {
	case "sha1":
		return sha1.New
	case "sha256":
		return sha256.New
	case "sha512":
		return sha512.New
	default:
		panic("unsupported digest")
	}
}

// Hash generates a PBKDF2 hash of the password with the given parameters.
// The hash format is $pbkdf2-<digest>$i=<iterations>$<salt>$<key>.
func Hash(password string, params Params) (string, error) {
	salt, err := randomBytes(params.SaltLen)
	if err != nil {
		return "", err
	}

	key := pbkdf2.Key([]byte(password), salt, params.Iterations, params.KeyLen, getHash(params.Digest))

	b64Salt := base64.StdEncoding.EncodeToString(salt)
	b64Key := base64.StdEncoding.EncodeToString(key)

	hashed := fmt.Sprintf("$pbkdf2-%s$i=%d$%s$%s", params.Digest, params.Iterations, b64Salt, b64Key)
	return hashed, nil
}

func parseHashed(hashed string) (key, salt []byte, params Params, err error) {
	parts := strings.Split(hashed, "$")
	if len(parts) != 5 {
		err = fmt.Errorf("invalid format")
		return
	}

	algoParamList := strings.Split(parts[1], "-")
	if len(algoParamList) != 2 {
		err = fmt.Errorf("invalid format: algorithm")
		return
	}
	if algoParamList[0] != "pbkdf2" {
		err = fmt.Errorf("invalid format: algorithm")
		return
	}
	params.Digest = algoParamList[1]

	paramList := strings.Split(parts[2], ",")
	for _, param := range paramList {
		kv := strings.Split(param, "=")
		if len(kv) != 2 {
			err = fmt.Errorf("invalid format: param")
			return
		}

		val, err1 := strconv.Atoi(kv[1])
		if err1 != nil {
			err = err1
			return
		}

		switch kv[0] {
		case "i", "I":
			params.Iterations = val
		}
	}

	salt, err = base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		err = fmt.Errorf("invalid format: salt")
		return
	}

	key, err = base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		err = fmt.Errorf("invalid format: key")
		return
	}
	params.KeyLen = len(key)

	return
}

// Verify checks if the password matches the hashed value.
// It uses constant-time comparison to prevent timing attacks.
func Verify(password, hashed string) (bool, error) {
	key, salt, params, err := parseHashed(hashed)
	if err != nil {
		return false, err
	}

	expectKey := pbkdf2.Key([]byte(password), salt, params.Iterations, params.KeyLen, getHash(params.Digest))
	return subtle.ConstantTimeCompare(key, expectKey) == 1, nil
}
