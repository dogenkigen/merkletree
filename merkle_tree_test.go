package main

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMerkleTree_Hash(t *testing.T) {
	nodes := []*Leaf{
		NewLeaf([]byte("one")),
		NewLeaf([]byte("two")),
		NewLeaf([]byte("three")),
		NewLeaf([]byte("four")),
		NewLeaf([]byte("five")),
		NewLeaf([]byte("six")),
	}
	merkleTree, err := NewMerkleTree(nodes, SHA256Hasher)
	require.NoError(t, err)
	hash, err := hex.DecodeString("1a32595799cc2f3ac6c91dcfed07ce8de07b67edfe871dda7d357ff21c76b554")
	require.NoError(t, err)
	assert.Equal(t, hash, merkleTree.Hash())
}

func TestMerkleTree_VerifyProof(t *testing.T) {
	nodes := []*Leaf{
		NewLeaf([]byte("one")),
		NewLeaf([]byte("two")),
		NewLeaf([]byte("three")),
		NewLeaf([]byte("four")),
		NewLeaf([]byte("five")),
		NewLeaf([]byte("six")),
		NewLeaf([]byte("seven")),
		NewLeaf([]byte("eight")),
	}
	merkleTree, err := NewMerkleTree(nodes, SHA256Hasher)
	require.NoError(t, err)

	testCases := []struct {
		name  string
		proof func() *Proof
		err   error
	}{
		{
			"right leaf",
			func() *Proof {
				leafHash, err := hex.DecodeString("c195d2d8756234367242ba7616c5c60369bc25ced2dcb5b92808d31b58ef217a")
				require.NoError(t, err)
				sibling1, err := hex.DecodeString("3ba8d02b16fd2a01c1a8ba1a1f036d7ce386ed953696fa57331c2ac48a80b255")
				require.NoError(t, err)
				sibling2, err := hex.DecodeString("e8d9085db3c97d5e40fe299fe102babfda2b042b88c49cc37a435756b75b6398")
				require.NoError(t, err)
				sibling3, err := hex.DecodeString("9d25f7b28617bd7c8b577828a1361dae4808415a688b1ca30c3521806a340ca9")
				require.NoError(t, err)
				return NewProof(7, leafHash, [][]byte{
					sibling1,
					sibling2,
					sibling3,
				})
			},
			nil,
		},
		{
			"left leaf",
			func() *Proof {
				leafHash, err := hex.DecodeString("7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed")
				require.NoError(t, err)
				sibling1, err := hex.DecodeString("3fc4ccfe745870e2c0d99f71f30ff0656c8dedd41cc1d7d3d376b0dbe685e2f3")
				require.NoError(t, err)
				sibling2, err := hex.DecodeString("7a1331d889641d862927f57aa85bc257b907203761d7ffbe2809dbc927f27531")
				require.NoError(t, err)
				sibling3, err := hex.DecodeString("e9b303c22512a3f4dd754db2125ff975210168d95809a90a7587e93d5ff29a98")
				require.NoError(t, err)
				return NewProof(0, leafHash, [][]byte{
					sibling1,
					sibling2,
					sibling3,
				})
			},
			nil,
		},
		{
			"leaf hash mismatch",
			func() *Proof {
				leafHash, err := hex.DecodeString("1692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed")
				require.NoError(t, err)
				sibling1, err := hex.DecodeString("3fc4ccfe745870e2c0d99f71f30ff0656c8dedd41cc1d7d3d376b0dbe685e2f3")
				require.NoError(t, err)
				sibling2, err := hex.DecodeString("7a1331d889641d862927f57aa85bc257b907203761d7ffbe2809dbc927f27531")
				require.NoError(t, err)
				sibling3, err := hex.DecodeString("e9b303c22512a3f4dd754db2125ff975210168d95809a90a7587e93d5ff29a98")
				require.NoError(t, err)
				return NewProof(0, leafHash, [][]byte{
					sibling1,
					sibling2,
					sibling3,
				})
			},
			leafHashMismatch,
		},
		{
			"wrong proof",
			func() *Proof {
				leafHash, err := hex.DecodeString("7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed")
				require.NoError(t, err)
				sibling1, err := hex.DecodeString("3fc4ccfe745870e2c0d99f71f30ff0656c8dedd41cc1d7d3d376b0dbe685e2f3")
				require.NoError(t, err)
				sibling2, err := hex.DecodeString("7a1331d889641d862927f57aa85bc257b907203761d7ffbe2809dbc927f27531")
				require.NoError(t, err)
				sibling3, err := hex.DecodeString("a9b303c22512a3f4dd754db2125ff975210168d95809a90a7587e93d5ff29a98")
				require.NoError(t, err)
				return NewProof(0, leafHash, [][]byte{
					sibling1,
					sibling2,
					sibling3,
				})
			},
			wrongProof,
		},
		{
			"leaf index out of bound",
			func() *Proof {
				return NewProof(100, []byte{}, [][]byte{})
			},
			leafIndexOutOfBound,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err != nil {
				assert.EqualError(t, merkleTree.VerifyProof(tc.proof()), tc.err.Error())
			} else {
				assert.NoError(t, merkleTree.VerifyProof(tc.proof()))
			}
		})
	}
}

func TestMerkleTree_GenerateProof(t *testing.T) {
	testCases := []struct {
		name  string
		tree  func() *MerkleTree
		idx   int
		proof func() *Proof
		err   error
	}{
		{
			"nine left",
			func() *MerkleTree {
				tree, err := NewMerkleTree([]*Leaf{
					NewLeaf([]byte("one")),
					NewLeaf([]byte("two")),
					NewLeaf([]byte("three")),
					NewLeaf([]byte("four")),
					NewLeaf([]byte("five")),
					NewLeaf([]byte("six")),
					NewLeaf([]byte("seven")),
					NewLeaf([]byte("eight")),
					NewLeaf([]byte("nine")),
				}, SHA256Hasher)
				require.NoError(t, err)
				return tree
			},
			8,
			func() *Proof {
				leafHash, err := hex.DecodeString("edcd8e701a2df0cd66a39bae6aa156cf16fe2b9653ef65f7d31742e2352421e4")
				require.NoError(t, err)
				sibling1, err := hex.DecodeString("edcd8e701a2df0cd66a39bae6aa156cf16fe2b9653ef65f7d31742e2352421e4")
				require.NoError(t, err)
				sibling2, err := hex.DecodeString("596995fdb0ff2b64d37c5ea77078a4651f1234dcdc18ab4a28c0712271fc8358")
				require.NoError(t, err)
				sibling3, err := hex.DecodeString("738e199d782689479b3c819eea73568c126bba4016a6ec46b8ce1cc30d2bd31f")
				require.NoError(t, err)
				sibling4, err := hex.DecodeString("01612bca71b4c88ba12c501dd86c844824e40b2dcd2ce82e5870d6bd94b6a4d7")
				require.NoError(t, err)
				return NewProof(8, leafHash, [][]byte{
					sibling1,
					sibling2,
					sibling3,
					sibling4,
				})
			},
			nil,
		},
		{
			"eight right",
			func() *MerkleTree {
				tree, err := NewMerkleTree([]*Leaf{
					NewLeaf([]byte("one")),
					NewLeaf([]byte("two")),
					NewLeaf([]byte("three")),
					NewLeaf([]byte("four")),
					NewLeaf([]byte("five")),
					NewLeaf([]byte("six")),
					NewLeaf([]byte("seven")),
					NewLeaf([]byte("eight")),
				}, SHA256Hasher)
				require.NoError(t, err)
				return tree
			},
			7,
			func() *Proof {
				leafHash, err := hex.DecodeString("c195d2d8756234367242ba7616c5c60369bc25ced2dcb5b92808d31b58ef217a")
				require.NoError(t, err)
				sibling1, err := hex.DecodeString("3ba8d02b16fd2a01c1a8ba1a1f036d7ce386ed953696fa57331c2ac48a80b255")
				require.NoError(t, err)
				sibling2, err := hex.DecodeString("e8d9085db3c97d5e40fe299fe102babfda2b042b88c49cc37a435756b75b6398")
				require.NoError(t, err)
				sibling3, err := hex.DecodeString("9d25f7b28617bd7c8b577828a1361dae4808415a688b1ca30c3521806a340ca9")
				require.NoError(t, err)
				return NewProof(7, leafHash, [][]byte{
					sibling1,
					sibling2,
					sibling3,
				})
			},
			nil,
		},
		{
			"six right",
			func() *MerkleTree {
				tree, err := NewMerkleTree([]*Leaf{
					NewLeaf([]byte("one")),
					NewLeaf([]byte("two")),
					NewLeaf([]byte("three")),
					NewLeaf([]byte("four")),
					NewLeaf([]byte("five")),
					NewLeaf([]byte("six")),
				}, SHA256Hasher)
				require.NoError(t, err)
				return tree
			},
			5,
			func() *Proof {
				leafHash, err := hex.DecodeString("44778d82365e4af681c40d5f0eef5cf6f5899d3f0ac335050a7ed6779cf3f674")
				require.NoError(t, err)
				sibling1, err := hex.DecodeString("222b0bd51fcef7e65c2e62db2ed65457013bab56be6fafeb19ee11d453153c80")
				require.NoError(t, err)
				sibling2, err := hex.DecodeString("e8d9085db3c97d5e40fe299fe102babfda2b042b88c49cc37a435756b75b6398")
				require.NoError(t, err)
				sibling3, err := hex.DecodeString("9d25f7b28617bd7c8b577828a1361dae4808415a688b1ca30c3521806a340ca9")
				require.NoError(t, err)
				return NewProof(5, leafHash, [][]byte{
					sibling1,
					sibling2,
					sibling3,
				})
			},
			nil,
		},
		{
			"leaf index out of bound",
			func() *MerkleTree {
				tree, err := NewMerkleTree([]*Leaf{
					NewLeaf([]byte("one")),
				}, SHA256Hasher)
				require.NoError(t, err)
				return tree
			},
			2,
			func() *Proof {
				return nil
			},
			leafIndexOutOfBound,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tree := tc.tree()
			proof, err := tree.GenerateProof(tc.idx)
			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.True(t, proof.Equal(tc.proof()))
				assert.NoError(t, tree.VerifyProof(proof))
			}
		})
	}
}

func TestMerkleTree_GenerateProof_Iterations(t *testing.T) {
	hashers := map[string]Hasher{
		"md5":        MD5Hasher,
		"sha256":     SHA256Hasher,
		"sha512":     SHA512Hasher,
		"blake2b246": Blake2b256Hasher,
		"blake2b512": Blake2b512Hasher,
	}
	for name, hasher := range hashers {
		t.Run(name, func(t *testing.T) {
			for i := 1; i < 100; i++ {
				leaves := make([]*Leaf, 0, i)
				for j := 0; j < i; j++ {
					leaves = append(leaves, NewLeaf([]byte(fmt.Sprintf("%d", j))))
				}
				tree, err := NewMerkleTree(leaves, hasher)
				require.NoError(t, err)
				for j := 0; j < i; j++ {
					proof, err := tree.GenerateProof(j)
					require.NoError(t, err)
					err = tree.VerifyProof(proof)
					assert.NoError(t, err, fmt.Sprintf("for %d leaves and index=%d", i, j))
				}
			}
		})
	}
}

func TestMerkleTree_Append(t *testing.T) {
	tree, err := NewMerkleTree([]*Leaf{
		NewLeaf([]byte("one")),
		NewLeaf([]byte("two")),
		NewLeaf([]byte("three")),
		NewLeaf([]byte("four")),
		NewLeaf([]byte("five")),
		NewLeaf([]byte("six")),
	}, SHA256Hasher)
	require.NoError(t, err)
	require.Equal(t, 6, len(tree.leaves))

	tree.Append(NewLeaf([]byte("seven")))

	assert.Equal(t, 7, len(tree.leaves))
}

func TestMerkleTree_String(t *testing.T) {
	tree, err := NewMerkleTree([]*Leaf{
		NewLeaf([]byte("one")),
		NewLeaf([]byte("two")),
		NewLeaf([]byte("three")),
		NewLeaf([]byte("four")),
		NewLeaf([]byte("five")),
	}, SHA256Hasher)
	require.NoError(t, err)

	assert.Equal(t, treeString, tree.String())
}

const treeString = `(hash: d22fcd08bc1dfb62432f9cb6c99e70491fb5aa6c56bfb7ed999339fbbbca0b37) |l (hash: 9d25f7b28617bd7c8b577828a1361dae4808415a688b1ca30c3521806a340ca9) |l (hash: 11914c19a28a98c57d12f3cce6c32b7944784f4b4781a706c24eb1dc284e2856) |l (content: one, hash: 7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed)
                                                                         |                                                                           |                                                                           |r (content: two, hash: 3fc4ccfe745870e2c0d99f71f30ff0656c8dedd41cc1d7d3d376b0dbe685e2f3)
                                                                         |                                                                           |r (hash: 7a1331d889641d862927f57aa85bc257b907203761d7ffbe2809dbc927f27531) |l (content: three, hash: 8b5b9db0c13db24256c829aa364aa90c6d2eba318b9232a4ab9313b954d3555f)
                                                                         |                                                                                                                                                       |r (content: four, hash: 04efaf080f5a3e74e1c29d1ca6a48569382cbbcd324e8d59d2b83ef21c039f00)
                                                                         |r (hash: c61670c8ab219819d23800f13aeb18b36816c39b479d98f755397b46d461f8ba) |l (hash: 1560f46a8f24c5a167580b38afe45fdec3be6f8aee90c1373f5853d8e06c7b17) |l (content: five, hash: 222b0bd51fcef7e65c2e62db2ed65457013bab56be6fafeb19ee11d453153c80)
                                                                                                                                                     |                                                                           |r (content: five, hash: 222b0bd51fcef7e65c2e62db2ed65457013bab56be6fafeb19ee11d453153c80)
                                                                                                                                                     |r (hash: 1560f46a8f24c5a167580b38afe45fdec3be6f8aee90c1373f5853d8e06c7b17)
`
