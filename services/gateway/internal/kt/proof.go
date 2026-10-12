package kt

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
)

const transparencySMTDepth = 256

var (
	smtLeafPrefix = []byte{0x00}
	smtNodePrefix = []byte{0x01}
	rfcLeafPrefix = []byte{0x00}
	rfcNodePrefix = []byte{0x01}
)

// SMTLeaf is one committed current-state entry.
type SMTLeaf struct {
	Key      [32]byte
	LeafHash [32]byte
}

func hashParts(parts ...[]byte) [32]byte {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write(part)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func smtLeafNode(leafHash [32]byte) [32]byte {
	return hashParts(smtLeafPrefix, leafHash[:])
}

func smtNode(left, right [32]byte) [32]byte {
	return hashParts(smtNodePrefix, left[:], right[:])
}

func smtBit(key [32]byte, depth int) byte {
	return (key[depth/8] >> (7 - (depth % 8))) & 1
}

func smtEmptyHashes() [transparencySMTDepth + 1][32]byte {
	var out [transparencySMTDepth + 1][32]byte
	out[0] = hashParts(smtLeafPrefix)
	for i := 0; i < transparencySMTDepth; i++ {
		out[i+1] = smtNode(out[i], out[i])
	}
	return out
}

var cachedSMTEmpty = smtEmptyHashes()

func smtRootRec(items []SMTLeaf, depth int) [32]byte {
	if len(items) == 0 {
		return cachedSMTEmpty[transparencySMTDepth-depth]
	}
	if depth == transparencySMTDepth {
		return smtLeafNode(items[0].LeafHash)
	}
	split := 0
	for split < len(items) && smtBit(items[split].Key, depth) == 0 {
		split++
	}
	return smtNode(
		smtRootRec(items[:split], depth+1),
		smtRootRec(items[split:], depth+1),
	)
}

func normalizeSMTLeaves(entries []SMTLeaf) ([]SMTLeaf, error) {
	sorted := append([]SMTLeaf(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i].Key[:], sorted[j].Key[:]) < 0 })
	for i := 1; i < len(sorted); i++ {
		if sorted[i-1].Key == sorted[i].Key {
			return nil, errors.New("kt: duplicate SMT key")
		}
	}
	return sorted, nil
}

// SMTRootV1 computes the frozen 256-depth current-state SMT root.
func SMTRootV1(entries []SMTLeaf) ([32]byte, error) {
	sorted, err := normalizeSMTLeaves(entries)
	if err != nil {
		return [32]byte{}, err
	}
	return smtRootRec(sorted, 0), nil
}

// SMTInclusionProofV1 returns the frozen root-to-leaf sibling path.
func SMTInclusionProofV1(entries []SMTLeaf, targetKey [32]byte) ([32]byte, [][32]byte, error) {
	sorted, err := normalizeSMTLeaves(entries)
	if err != nil {
		return [32]byte{}, nil, err
	}
	found := false
	for _, entry := range sorted {
		if entry.Key == targetKey {
			found = true
			break
		}
	}
	if !found {
		return [32]byte{}, nil, fmt.Errorf("kt: SMT key not found")
	}

	siblings := make([][32]byte, 0, transparencySMTDepth)
	items := sorted
	for depth := 0; depth < transparencySMTDepth; depth++ {
		split := 0
		for split < len(items) && smtBit(items[split].Key, depth) == 0 {
			split++
		}
		if smtBit(targetKey, depth) == 0 {
			siblings = append(siblings, smtRootRec(items[split:], depth+1))
			items = items[:split]
		} else {
			siblings = append(siblings, smtRootRec(items[:split], depth+1))
			items = items[split:]
		}
	}
	root := smtRootRec(sorted, 0)
	return root, siblings, nil
}

// VerifySMTInclusionV1 verifies the frozen root-to-leaf sibling order.
func VerifySMTInclusionV1(targetKey, targetLeafHash [32]byte, siblingsRootToLeaf [][32]byte, expectedRoot [32]byte) error {
	if len(siblingsRootToLeaf) != transparencySMTDepth {
		return fmt.Errorf("kt: SMT proof has %d siblings, want %d", len(siblingsRootToLeaf), transparencySMTDepth)
	}
	acc := smtLeafNode(targetLeafHash)
	for depth := transparencySMTDepth - 1; depth >= 0; depth-- {
		sibling := siblingsRootToLeaf[depth]
		if smtBit(targetKey, depth) == 0 {
			acc = smtNode(acc, sibling)
		} else {
			acc = smtNode(sibling, acc)
		}
	}
	if acc != expectedRoot {
		return errors.New("kt: SMT root mismatch")
	}
	return nil
}

func rfcLeafHash(data []byte) [32]byte {
	return hashParts(rfcLeafPrefix, data)
}

func rfcNodeHash(left, right [32]byte) [32]byte {
	return hashParts(rfcNodePrefix, left[:], right[:])
}

func largestPowerLessThan(n int) int {
	if n <= 1 {
		return 0
	}
	k := 1
	for k < n {
		k <<= 1
	}
	return k >> 1
}

func historyMTH(hashes [][32]byte) [32]byte {
	switch len(hashes) {
	case 0:
		return hashParts(nil)
	case 1:
		return hashes[0]
	default:
		k := largestPowerLessThan(len(hashes))
		return rfcNodeHash(historyMTH(hashes[:k]), historyMTH(hashes[k:]))
	}
}

// HistoryRootV1 computes the RFC 6962-shaped history Merkle root.
func HistoryRootV1(entries [][]byte) [32]byte {
	hashes := make([][32]byte, len(entries))
	for i, entry := range entries {
		hashes[i] = rfcLeafHash(entry)
	}
	if len(entries) == 0 {
		return hashParts(nil)
	}
	return historyMTH(hashes)
}

func historyPath(hashes [][32]byte, index int) [][32]byte {
	if len(hashes) <= 1 {
		return nil
	}
	k := largestPowerLessThan(len(hashes))
	if index < k {
		proof := historyPath(hashes[:k], index)
		return append(proof, historyMTH(hashes[k:]))
	}
	proof := historyPath(hashes[k:], index-k)
	return append(proof, historyMTH(hashes[:k]))
}

// HistoryInclusionProofV1 returns the RFC 6962 audit path.
func HistoryInclusionProofV1(entries [][]byte, index int) ([][32]byte, error) {
	if index < 0 || index >= len(entries) {
		return nil, errors.New("kt: history index out of range")
	}
	hashes := make([][32]byte, len(entries))
	for i, entry := range entries {
		hashes[i] = rfcLeafHash(entry)
	}
	return historyPath(hashes, index), nil
}

// VerifyHistoryInclusionV1 verifies one history entry and its audit path.
func VerifyHistoryInclusionV1(entry []byte, index, treeSize int, proof [][32]byte, expectedRoot [32]byte) error {
	if index < 0 || index >= treeSize {
		return errors.New("kt: invalid history index")
	}
	hEntry, err := ParseHistoryEntryV1(entry)
	if err != nil {
		return fmt.Errorf("kt: invalid history entry: %w", err)
	}
	if hEntry.Sequence != uint64(index+1) {
		return errors.New("kt: history sequence does not match index")
	}
	acc := rfcLeafHash(entry)
	node := index
	last := treeSize - 1
	pi := 0
	for last > 0 {
		if pi >= len(proof) {
			return errors.New("kt: truncated history proof")
		}
		sibling := proof[pi]
		if node%2 == 1 || node == last {
			acc = rfcNodeHash(sibling, acc)
		} else {
			acc = rfcNodeHash(acc, sibling)
		}
		node /= 2
		last /= 2
		pi++
	}
	if pi != len(proof) || acc != expectedRoot {
		return errors.New("kt: history root mismatch")
	}
	return nil
}

func historyConsistencySubproof(hashes [][32]byte, m, n int, complete bool) [][32]byte {
	if m == n {
		if complete {
			return nil
		}
		return [][32]byte{historyMTH(hashes[:m])}
	}
	k := largestPowerLessThan(n)
	if m <= k {
		proof := historyConsistencySubproof(hashes[:k], m, k, complete)
		return append(proof, historyMTH(hashes[k:n]))
	}
	proof := historyConsistencySubproof(hashes[k:n], m-k, n-k, false)
	return append(proof, historyMTH(hashes[:k]))
}

// HistoryConsistencyProofV1 builds RFC 6962 PROOF(m,D[n]) for 0 < m < n.
func HistoryConsistencyProofV1(entries [][]byte, oldSize int) ([][32]byte, error) {
	if oldSize <= 0 || oldSize > len(entries) {
		return nil, errors.New("kt: invalid history consistency sizes")
	}
	hashes := make([][32]byte, len(entries))
	for i, entry := range entries {
		hashes[i] = rfcLeafHash(entry)
	}
	return historyConsistencySubproof(hashes, oldSize, len(entries), true), nil
}

// VerifyHistoryConsistencyV1 verifies an RFC 6962 consistency proof.
func VerifyHistoryConsistencyV1(oldSize, newSize int, oldRoot, newRoot [32]byte, proof [][32]byte) error {
	if oldSize < 0 || newSize < 0 || oldSize > newSize {
		return errors.New("kt: invalid consistency sizes")
	}
	if oldSize == newSize {
		if oldRoot == newRoot && len(proof) == 0 {
			return nil
		}
		return errors.New("kt: invalid equal-size consistency proof")
	}
	if oldSize == 0 {
		return errors.New("kt: zero-size old tree is outside V1 consistency operation")
	}
	node := oldSize - 1
	lastNode := newSize - 1
	for node%2 == 1 {
		node /= 2
		lastNode /= 2
	}
	pi := 0
	var oldHash, newHash [32]byte
	if node != 0 {
		if pi >= len(proof) {
			return errors.New("kt: truncated consistency proof")
		}
		oldHash, newHash = proof[pi], proof[pi]
		pi++
	} else {
		oldHash, newHash = oldRoot, oldRoot
	}
	for node != 0 {
		if node%2 == 1 {
			if pi >= len(proof) {
				return errors.New("kt: truncated consistency proof")
			}
			sibling := proof[pi]
			pi++
			oldHash = rfcNodeHash(sibling, oldHash)
			newHash = rfcNodeHash(sibling, newHash)
		} else if node < lastNode {
			if pi >= len(proof) {
				return errors.New("kt: truncated consistency proof")
			}
			newHash = rfcNodeHash(newHash, proof[pi])
			pi++
		}
		node /= 2
		lastNode /= 2
	}
	for lastNode != 0 {
		if pi >= len(proof) {
			return errors.New("kt: truncated consistency proof")
		}
		newHash = rfcNodeHash(newHash, proof[pi])
		pi++
		lastNode /= 2
	}
	if pi != len(proof) || oldHash != oldRoot || newHash != newRoot {
		return errors.New("kt: history consistency mismatch")
	}
	return nil
}
