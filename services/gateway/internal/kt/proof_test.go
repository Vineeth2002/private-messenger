package kt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type smtVector struct {
	RootHex string `json:"root_hex"`
	Proofs  []struct {
		LeafKeyHex            string   `json:"leaf_key_hex"`
		LeafHashHex           string   `json:"leaf_hash_hex"`
		SiblingsRootToLeafHex []string `json:"siblings_root_to_leaf_hex"`
	} `json:"proofs"`
}

type historyVector struct {
	TreeSize       int    `json:"tree_size"`
	HistoryRootHex string `json:"history_root_hex"`
	Entries        []struct {
		Sequence uint64 `json:"sequence"`
		EntryHex string `json:"entry_hex"`
	} `json:"entries"`
	Inclusion []struct {
		Sequence uint64   `json:"sequence"`
		Index    int      `json:"index"`
		EntryHex string   `json:"entry_hex"`
		ProofHex []string `json:"proof_hex"`
	} `json:"inclusion"`
	Consistency []struct {
		OldSize    int      `json:"old_size"`
		OldRootHex string   `json:"old_root_hex"`
		NewRootHex string   `json:"new_root_hex"`
		ProofHex   []string `json:"proof_hex"`
	} `json:"consistency"`
}

func readJSON(t *testing.T, name string, out any) {
	t.Helper()
	path := filepath.FromSlash("../../../../test-vectors/v1/" + name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatal(err)
	}
}

func decode32(t *testing.T, s string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		t.Fatalf("bad 32-byte hex %q", s)
	}
	var out [32]byte
	copy(out[:], raw)
	return out
}

func decode32List(t *testing.T, xs []string) [][32]byte {
	t.Helper()
	out := make([][32]byte, len(xs))
	for i, x := range xs {
		out[i] = decode32(t, x)
	}
	return out
}

func decodeBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSMTAlgorithmsMatchFrozenVector(t *testing.T) {
	var v smtVector
	readJSON(t, "transparency_smt_proofs.json", &v)
	entries := make([]SMTLeaf, len(v.Proofs))
	for i, p := range v.Proofs {
		entries[i] = SMTLeaf{Key: decode32(t, p.LeafKeyHex), LeafHash: decode32(t, p.LeafHashHex)}
	}
	root, err := SMTRootV1(entries)
	if err != nil {
		t.Fatal(err)
	}
	if root != decode32(t, v.RootHex) {
		t.Fatalf("SMT root mismatch: %x", root)
	}
	for _, p := range v.Proofs {
		key := decode32(t, p.LeafKeyHex)
		expected := decode32List(t, p.SiblingsRootToLeafHex)
		gotRoot, gotProof, err := SMTInclusionProofV1(entries, key)
		if err != nil {
			t.Fatal(err)
		}
		if gotRoot != root {
			t.Fatalf("proof root mismatch for %s", p.LeafKeyHex)
		}
		if len(gotProof) != len(expected) {
			t.Fatalf("proof length = %d want %d", len(gotProof), len(expected))
		}
		for i := range expected {
			if gotProof[i] != expected[i] {
				t.Fatalf("SMT sibling mismatch key=%s level=%d", p.LeafKeyHex, i)
			}
		}
		if err := VerifySMTInclusionV1(key, decode32(t, p.LeafHashHex), gotProof, root); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHistoryAlgorithmsMatchFrozenVector(t *testing.T) {
	var v historyVector
	readJSON(t, "transparency_history_proofs.json", &v)
	entries := make([][]byte, len(v.Entries))
	for i, entry := range v.Entries {
		entries[i] = decodeBytes(t, entry.EntryHex)
	}
	root := HistoryRootV1(entries)
	if root != decode32(t, v.HistoryRootHex) {
		t.Fatalf("history root mismatch: %x", root)
	}
	for _, inc := range v.Inclusion {
		got, err := HistoryInclusionProofV1(entries, inc.Index)
		if err != nil {
			t.Fatal(err)
		}
		want := decode32List(t, inc.ProofHex)
		if len(got) != len(want) {
			t.Fatalf("history proof length sequence=%d got=%d want=%d", inc.Sequence, len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("history proof mismatch sequence=%d level=%d", inc.Sequence, i)
			}
		}
		if err := VerifyHistoryInclusionV1(entries[inc.Index], inc.Index, v.TreeSize, got, root); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range v.Consistency {
		oldEntries := entries[:c.OldSize]
		oldRoot := HistoryRootV1(oldEntries)
		if oldRoot != decode32(t, c.OldRootHex) {
			t.Fatalf("old root mismatch old_size=%d", c.OldSize)
		}
		got, err := HistoryConsistencyProofV1(entries, c.OldSize)
		if err != nil {
			t.Fatal(err)
		}
		want := decode32List(t, c.ProofHex)
		if len(got) != len(want) {
			t.Fatalf("consistency proof length old_size=%d got=%d want=%d", c.OldSize, len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("consistency proof mismatch old_size=%d level=%d", c.OldSize, i)
			}
		}
		if err := VerifyHistoryConsistencyV1(c.OldSize, v.TreeSize, oldRoot, root, got); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProofAlgorithmsRejectTampering(t *testing.T) {
	entries := [][]byte{[]byte("one"), []byte("two"), []byte("three"), []byte("four")}
	root := HistoryRootV1(entries)
	proof, err := HistoryInclusionProofV1(entries, 1)
	if err != nil {
		t.Fatal(err)
	}
	proof[0][0] ^= 1
	if err := VerifyHistoryInclusionV1(entries[1], 1, len(entries), proof, root); err == nil {
		t.Fatal("tampered history proof accepted")
	}

	key1 := sha256.Sum256([]byte("key1"))
	key2 := sha256.Sum256([]byte("key2"))
	leaf1 := sha256.Sum256([]byte("leaf1"))
	leaf2 := sha256.Sum256([]byte("leaf2"))
	leaves := []SMTLeaf{{Key: key1, LeafHash: leaf1}, {Key: key2, LeafHash: leaf2}}
	smtRoot, smtProof, err := SMTInclusionProofV1(leaves, key1)
	if err != nil {
		t.Fatal(err)
	}
	smtProof[7][0] ^= 1
	if err := VerifySMTInclusionV1(key1, leaf1, smtProof, smtRoot); err == nil {
		t.Fatal("tampered SMT proof accepted")
	}
}
