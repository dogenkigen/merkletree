# MerkleTree

Merkle tree implementation in Go. It allows for efficient and secure verification of the contents of large data structures. When you insert data into the Merkle tree, it creates a unique digital fingerprint (hash) of your data. You can then use that fingerprint to verify that your data hasn't been tampered with.

## Usage
### Creating a Merkle Tree:

First, you'll need to define your hashing function. You can use pre-defined hashing functions or create your own

```go
hasher := func(data []byte) []byte {
    // implement your hashing function here
}
// or
hasher := gomerkletree.SHA256Hasher
```
Then, you can create your leaf nodes:
```go
leaf1 := NewLeaf([]byte("Hello"))
leaf2 := NewLeaf([]byte("World"))
```
Finally, create your Merkle tree:
```go
tree := NewMerkleTree([]*Leaf{leaf1, leaf2}, hasher)
```

### Appending to the Merkle Tree:
To add a new leaf to the Merkle tree:
```go
leaf3 := NewLeaf([]byte("GoMerkleTree"))
tree.Append(leaf3)
```

### Creating a Proof:
To create a proof for a leaf:
```go
proof, err := tree.GenerateProof(0)  // Generate proof for the first leaf
if err != nil {
    // handle error
}
```

### Verifying a Proof:
To verify a proof:
```go
err = tree.VerifyProof(proof)
if err != nil {
    // handle error
}
```

### Printing the Merkle Tree:
To visualize the Merkle tree:
```go
fmt.Println(tree)
```
