package main

import (
	"encoding/hex"
	"fmt"
	"strings"
)

type node interface {
	Hash() []byte
	hasChildren() bool
	getString(ident string) string
}

type Leaf struct {
	content    []byte
	cachedHash []byte
	hashFunc   func([]byte) []byte
}

func NewLeaf(content []byte) *Leaf {
	return &Leaf{content: content}
}

func (l *Leaf) Hash() []byte {
	if len(l.cachedHash) > 0 {
		return l.cachedHash
	}
	l.cachedHash = l.hashFunc(l.content)
	return l.cachedHash
}

func (l *Leaf) hasChildren() bool {
	return false
}

func (l *Leaf) getString(_ string) string {
	return fmt.Sprintf("(content: %s, hash: %s)", string(l.content), hex.EncodeToString(l.Hash()))
}

type nonLeaf struct {
	left       node
	right      node
	cachedHash []byte
	hashFunc   func([]byte) []byte
}

func newNonLeaf(left node, right node, hashFunc func([]byte) []byte) *nonLeaf {
	return &nonLeaf{left: left, right: right, hashFunc: hashFunc}
}

func (nl *nonLeaf) Hash() []byte {
	if len(nl.cachedHash) > 0 {
		return nl.cachedHash
	}
	nl.cachedHash = nl.hashFunc(append(nl.left.Hash(), nl.right.Hash()...))
	return nl.cachedHash
}

func (nl *nonLeaf) hasChildren() bool {
	return nl.left != nil && nl.right != nil
}

func (nl *nonLeaf) getString(ident string) string {
	own := fmt.Sprintf("(hash: %s)", hex.EncodeToString(nl.Hash()))
	if !nl.hasChildren() {
		return fmt.Sprintf("%s\n", own)
	}
	if len(ident) > 0 {
		ident = fmt.Sprintf("%s  ", ident)
	}
	for i := 0; i < len(own); i++ {
		ident = fmt.Sprintf("%s ", ident)
	}
	ident = fmt.Sprintf("%s |", ident)
	left := fmt.Sprintf(" |l %s", nl.left.getString(ident))
	right := fmt.Sprintf("r %s", nl.right.getString(replaceLast(ident, "|", " ")))
	return fmt.Sprintf("%s%s\n%s%s\n", own, left, ident, right)
}

func replaceLast(s, old, new string) string {
	i := strings.LastIndex(s, old)
	return s[:i] + strings.Replace(s[i:], old, new, 1)
}
