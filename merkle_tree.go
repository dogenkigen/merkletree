package main

import (
	"bytes"
	"regexp"
)

// MerkleTree represents a Merkle tree data structure.
type MerkleTree struct {
	root   node
	leaves []*Leaf
	hasher Hasher
}

// NewMerkleTree creates a new Merkle tree given a set of leaves and a hashing function.
func NewMerkleTree(leaves []*Leaf, hasher Hasher) (*MerkleTree, error) {
	if len(leaves) == 0 {
		return nil, emptyTree
	}
	for _, l := range leaves {
		l.hashFunc = hasher
	}
	return &MerkleTree{leaves: leaves, hasher: hasher, root: buildRoot(leaves, hasher)}, nil
}

// VerifyProof checks the provided proof against the Merkle tree.
// It returns an error if the proof is invalid or doesn't correspond to any leaf in the tree.
func (mt *MerkleTree) VerifyProof(proof *Proof) error {
	if proof.leafIndex < 0 || proof.leafIndex >= len(mt.leaves) {
		return leafIndexOutOfBound
	}
	currentHash := proof.leafHash
	if !bytes.Equal(currentHash, mt.leaves[proof.leafIndex].Hash()) {
		return leafHashMismatch
	}
	for i, sibling := range proof.siblingHashes {
		if (proof.leafIndex>>i)&1 == 0 {
			currentHash = mt.hasher(append(currentHash, sibling...))
		} else {
			currentHash = mt.hasher(append(sibling, currentHash...))
		}
	}
	if !bytes.Equal(currentHash, mt.root.Hash()) {
		return wrongProof
	}
	return nil
}

// GenerateProof creates a proof for the leaf at the provided index.
// It returns an error if the index is out of bounds.
func (mt *MerkleTree) GenerateProof(idx int) (*Proof, error) {
	if idx < 0 || idx >= len(mt.leaves) {
		return nil, leafIndexOutOfBound
	}
	siblingHashes := collectSiblingsHashes(mt.root, nil, make([][]byte, 0, len(mt.leaves)/2), len(mt.leaves), idx)
	return NewProof(idx, mt.leaves[idx].Hash(), siblingHashes), nil
}

func collectSiblingsHashes(n, sibling node, siblingHashes [][]byte, remainingLen, tmpIdx int) [][]byte {
	switch n.(type) {
	case *Leaf:
		siblingHashes = append(siblingHashes, sibling.Hash())
	case *nonLeaf:
		powerOf2 := nearestSmallerPowerOf2(remainingLen)
		left := n.(*nonLeaf).left
		right := n.(*nonLeaf).right
		emptyNonLeafRight := false
		_, ok := right.(*nonLeaf)
		if ok {
			emptyNonLeafRight = !right.hasChildren()
		}
		if emptyNonLeafRight {
			siblingHashes = collectSiblingsHashes(left, right, siblingHashes, remainingLen, tmpIdx)
		} else if powerOf2 >= tmpIdx+1 {
			siblingHashes = collectSiblingsHashes(left, right, siblingHashes, powerOf2, tmpIdx)
		} else {
			siblingHashes = collectSiblingsHashes(right, left, siblingHashes, remainingLen-powerOf2, tmpIdx-powerOf2)
		}
		if sibling != nil {
			siblingHashes = append(siblingHashes, sibling.Hash())
		}
	}
	return siblingHashes
}

func nearestSmallerPowerOf2(n int) int {
	if n < 1 {
		return 0
	}
	power := 1
	for power <= n/2 {
		power *= 2
	}
	if power == n {
		return power / 2
	}
	return power
}

// Hash returns the root hash of the Merkle tree.
func (mt *MerkleTree) Hash() []byte {
	return mt.root.Hash()
}

// Append adds new leaves to the Merkle tree.
// The root of the tree is recalculated after appending the leaves.
func (mt *MerkleTree) Append(leaves ...*Leaf) {
	for _, leaf := range leaves {
		leaf.hashFunc = mt.hasher
	}
	mt.leaves = append(mt.leaves, leaves...)
	mt.root = buildRoot(mt.leaves, mt.hasher)
}

// String returns a string representation of the Merkle tree.
func (mt *MerkleTree) String() string {
	return regexp.MustCompile("\n\n+").ReplaceAllString(mt.root.getString(""), "\n")
}

func buildRoot[T node](nodes []T, hasher Hasher) node {
	if len(nodes) == 1 {
		if nodes[0].hasChildren() {
			return nodes[0]
		} else {
			return newNonLeaf(nodes[0], nodes[0], hasher)
		}
	}
	parents := make([]node, 0, (len(nodes)/2)+1)
	var left node
	var right node
	for _, n := range nodes {
		if left == nil {
			left = n
		} else if right == nil {
			right = n
		}
		if left != nil && right != nil {
			parents = append(parents, newNonLeaf(left, right, hasher))
			left = nil
			right = nil
		}
	}
	if left != nil && right == nil {
		var r node
		if left.hasChildren() {
			r = &nonLeaf{cachedHash: left.Hash()}
		} else {
			r = left
		}
		parents = append(parents, newNonLeaf(left, r, hasher))
	}
	return buildRoot(parents, hasher)
}
