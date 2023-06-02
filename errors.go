package main

import "errors"

var (
	wrongProof          = errors.New("calculated hash doesn't match the root hash of the tree")
	leafIndexOutOfBound = errors.New("provided leaf index doesn't exist")
	leafHashMismatch    = errors.New("provided leaf hash doesn't match with hash of the leaf")
	emptyTree           = errors.New("cannot create empty tree")
)
