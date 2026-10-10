package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	passwordSaltLength = 16
	passwordHashLength = 32
	minArgonMemory     = uint32(19 * 1024)
	maxArgonMemory     = uint32(64 * 1024)
	minArgonIterations = uint32(2)
	maxArgonIterations = uint32(4)
	minArgonThreads    = uint8(1)
	maxArgonThreads    = uint8(4)
)

type argonParameters struct {
	memory     uint32
	iterations uint32
	parallel   uint8
}

func hashPassword(password string, params argonParameters) (string, error) {
	salt := make([]byte, passwordSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt")
	}
	result := argon2.IDKey([]byte(password), salt, params.iterations, params.memory, params.parallel, passwordHashLength)
	return fmt.Sprintf("v=1$argon2id$m=%d,t=%d,p=%d$%s$%s",
		params.memory, params.iterations, params.parallel,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(result)), nil
}

func verifyPassword(encoded, password string) (bool, *argonParameters, error) {
	if len(encoded) > 256 {
		return false, nil, fmt.Errorf("password verifier is too large")
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "v=1" || parts[1] != "argon2id" {
		return false, nil, fmt.Errorf("unsupported password verifier")
	}
	parameters := strings.Split(parts[2], ",")
	if len(parameters) != 3 || !strings.HasPrefix(parameters[0], "m=") || !strings.HasPrefix(parameters[1], "t=") || !strings.HasPrefix(parameters[2], "p=") {
		return false, nil, fmt.Errorf("invalid password verifier parameters")
	}
	memory, err := strconv.ParseUint(strings.TrimPrefix(parameters[0], "m="), 10, 32)
	if err != nil {
		return false, nil, fmt.Errorf("invalid password verifier memory")
	}
	iterations, err := strconv.ParseUint(strings.TrimPrefix(parameters[1], "t="), 10, 32)
	if err != nil {
		return false, nil, fmt.Errorf("invalid password verifier iterations")
	}
	parallel, err := strconv.ParseUint(strings.TrimPrefix(parameters[2], "p="), 10, 8)
	if err != nil {
		return false, nil, fmt.Errorf("invalid password verifier parallelism")
	}
	params := argonParameters{memory: uint32(memory), iterations: uint32(iterations), parallel: uint8(parallel)}
	if params.memory < minArgonMemory || params.memory > maxArgonMemory || params.iterations < minArgonIterations || params.iterations > maxArgonIterations || params.parallel < minArgonThreads || params.parallel > maxArgonThreads {
		return false, nil, fmt.Errorf("password verifier parameters outside allowed range")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(salt) < passwordSaltLength || len(salt) > 64 {
		return false, nil, fmt.Errorf("invalid password verifier salt")
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(expected) != passwordHashLength {
		return false, nil, fmt.Errorf("invalid password verifier result")
	}
	actual := argon2.IDKey([]byte(password), salt, params.iterations, params.memory, params.parallel, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1, &params, nil
}

func needsRehash(stored, current argonParameters) bool {
	return stored.memory < current.memory || stored.iterations < current.iterations || stored.parallel < current.parallel
}

func upgradeParameters(stored, current argonParameters) argonParameters {
	if stored.memory > current.memory {
		current.memory = stored.memory
	}
	if stored.iterations > current.iterations {
		current.iterations = stored.iterations
	}
	if stored.parallel > current.parallel {
		current.parallel = stored.parallel
	}
	return current
}
