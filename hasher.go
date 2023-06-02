package main

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"golang.org/x/crypto/blake2b"
)

// Hasher is a function type that represents a hashing function. It takes a byte slice
// and returns another byte slice representing the hash of the input.
type Hasher func(data []byte) []byte

var (

	// SHA256Hasher is a Hasher that implements the SHA-256 hash algorithm.
	// It returns the SHA-256 hash of the input data as a byte slice.
	SHA256Hasher = func(data []byte) []byte {
		result := sha256.Sum256(data)
		return result[:]
	}

	// SHA512Hasher is a Hasher that implements the SHA-512 hash algorithm.
	// It returns the SHA-512 hash of the input data as a byte slice.
	SHA512Hasher = func(data []byte) []byte {
		result := sha512.Sum512(data)
		return result[:]
	}

	// Blake2b256Hasher is a Hasher that implements the Blake2b-256 hash algorithm.
	// It returns the Blake2b-256 hash of the input data as a byte slice.
	Blake2b256Hasher = func(data []byte) []byte {
		result := blake2b.Sum256(data)
		return result[:]
	}

	// Blake2b512Hasher is a Hasher that implements the Blake2b-512 hash algorithm.
	// It returns the Blake2b-512 hash of the input data as a byte slice.
	Blake2b512Hasher = func(data []byte) []byte {
		result := blake2b.Sum512(data)
		return result[:]
	}

	// MD5Hasher is a Hasher that implements the MD5 hash algorithm.
	// It returns the MD5 hash of the input data as a byte slice.
	MD5Hasher = func(data []byte) []byte {
		result := md5.Sum(data)
		return result[:]
	}
)
