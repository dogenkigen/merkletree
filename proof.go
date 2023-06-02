package main

import "bytes"

// Proof represents a proof of inclusion in a Merkle tree.
// It consists of the index of a leaf, the hash of the leaf and
// the hashes of the siblings of the nodes on the path from the leaf to the root.
type Proof struct {
	leafIndex     int
	leafHash      []byte
	siblingHashes [][]byte
}

// NewProof creates a new instance of Proof given a leaf index, a leaf hash and a list of sibling hashes.
func NewProof(leafIndex int, leafHash []byte, siblingHashes [][]byte) *Proof {
	return &Proof{leafIndex: leafIndex, leafHash: leafHash, siblingHashes: siblingHashes}
}

// Equal checks the equality of the current Proof with another Proof.
// Two proofs are equal if their leaf index, leaf hash and all sibling hashes are identical.
func (p *Proof) Equal(other *Proof) bool {
	if p.leafIndex != other.leafIndex {
		return false
	}
	if !bytes.Equal(p.leafHash, other.leafHash) {
		return false
	}
	if len(p.siblingHashes) != len(other.siblingHashes) {
		return false
	}
	for i, hash := range p.siblingHashes {
		if !bytes.Equal(hash, other.siblingHashes[i]) {
			return false
		}
	}
	return true
}
