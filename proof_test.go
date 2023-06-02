package merkletree

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestProof_Equals(t *testing.T) {
	testCases := []struct {
		name     string
		proof    *Proof
		other    *Proof
		expected bool
	}{
		{
			"same proofs",
			NewProof(0, []byte{1, 2, 3}, [][]byte{{4, 5, 6}, {7, 8, 9}}),
			NewProof(0, []byte{1, 2, 3}, [][]byte{{4, 5, 6}, {7, 8, 9}}),
			true,
		},
		{
			"different leaf indices",
			NewProof(0, []byte{1, 2, 3}, [][]byte{{4, 5, 6}, {7, 8, 9}}),
			NewProof(1, []byte{1, 2, 3}, [][]byte{{4, 5, 6}, {7, 8, 9}}),
			false,
		},
		{
			"different leaf hashes",
			NewProof(0, []byte{1, 2, 3}, [][]byte{{4, 5, 6}, {7, 8, 9}}),
			NewProof(0, []byte{10, 11, 12}, [][]byte{{4, 5, 6}, {7, 8, 9}}),
			false,
		},
		{
			"different sibling hashes length",
			NewProof(0, []byte{1, 2, 3}, [][]byte{{4, 5, 6}, {7, 8, 9}}),
			NewProof(0, []byte{1, 2, 3}, [][]byte{{4, 5, 6}}),
			false,
		},
		{
			"different sibling hashes",
			NewProof(0, []byte{1, 2, 3}, [][]byte{{4, 5, 6}, {7, 8, 9}}),
			NewProof(0, []byte{1, 2, 3}, [][]byte{{4, 5, 6}, {10, 11, 12}}),
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.proof.Equal(tc.other))
		})
	}
}
