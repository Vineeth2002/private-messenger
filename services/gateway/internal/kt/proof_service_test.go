package kt

import (
	"context"
	"errors"
	"testing"
	"time"
)

type memoryTransparencyState struct {
	current []SMTLeaf
	history [][]byte
}

func (m *memoryTransparencyState) CurrentState(context.Context) ([]SMTLeaf, error) {
	return append([]SMTLeaf(nil), m.current...), nil
}
func (m *memoryTransparencyState) HistoryEntries(context.Context) ([][]byte, error) {
	out := make([][]byte, len(m.history))
	for i := range m.history {
		out[i] = append([]byte(nil), m.history[i]...)
	}
	return out, nil
}

type memoryTransparencySTH struct {
	sth SignedTreeHeadV1
	raw []byte
	err error
}

func (m *memoryTransparencySTH) Latest(context.Context) (SignedTreeHeadV1, []byte, time.Time, error) {
	if m.err != nil {
		return SignedTreeHeadV1{}, nil, time.Time{}, m.err
	}
	return m.sth, append([]byte(nil), m.raw...), time.Unix(1, 0).UTC(), nil
}

func makeTestHistoryEntry(sequence byte, key, leaf [32]byte) []byte {
	// Canonical PM-CBOR map {1:sequence, 2:key, 3:leaf} for sequence=1.
	// This helper is intentionally used only with sequence=1 in these tests.
	raw := make([]byte, 0, 71)
	raw = append(raw, 0xa3, 0x01, sequence, 0x02, 0x58, 0x20)
	raw = append(raw, key[:]...)
	raw = append(raw, 0x03, 0x58, 0x20)
	raw = append(raw, leaf[:]...)
	return raw
}

func TestCurrentStateProofBindsGeneratedProofsToSTH(t *testing.T) {
	var key, leaf [32]byte
	key[31] = 1
	leaf[31] = 2
	historyEntry := makeTestHistoryEntry(1, key, leaf)
	state := &memoryTransparencyState{
		current: []SMTLeaf{{Key: key, LeafHash: leaf}},
		history: [][]byte{historyEntry},
	}
	smtRoot, _, err := SMTInclusionProofV1(state.current, key)
	if err != nil {
		t.Fatal(err)
	}
	historyRoot := HistoryRootV1(state.history)
	sth := &memoryTransparencySTH{sth: SignedTreeHeadV1{
		TreeSize:    1,
		SMTRoot:     smtRoot,
		HistoryRoot: historyRoot,
	}, raw: []byte{0xaa}}

	bundle, err := NewTransparencyProofService(state, sth).CurrentStateProof(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.TreeSize != 1 || bundle.HistorySequence != 1 || bundle.HistoryIndex != 0 {
		t.Fatalf("unexpected bundle metadata: %+v", bundle)
	}
	if len(bundle.SMTSiblings) != transparencySMTDepth {
		t.Fatalf("SMT siblings = %d", len(bundle.SMTSiblings))
	}
	if len(bundle.HistoryProof) != 0 {
		t.Fatalf("single-entry history proof length = %d", len(bundle.HistoryProof))
	}
	if string(bundle.SignedTreeHead) != string([]byte{0xaa}) {
		t.Fatal("STH bytes not retained")
	}
}

func TestCurrentStateProofRejectsSTHRootMismatch(t *testing.T) {
	var key, leaf [32]byte
	key[31] = 1
	leaf[31] = 2
	history := [][]byte{makeTestHistoryEntry(1, key, leaf)}
	state := &memoryTransparencyState{current: []SMTLeaf{{Key: key, LeafHash: leaf}}, history: history}
	sth := &memoryTransparencySTH{sth: SignedTreeHeadV1{TreeSize: 1}}
	if _, err := NewTransparencyProofService(state, sth).CurrentStateProof(context.Background(), key); err == nil {
		t.Fatal("expected STH root mismatch")
	}
}

func TestCurrentStateProofPropagatesSTHReadFailure(t *testing.T) {
	var key, leaf [32]byte
	key[31] = 1
	leaf[31] = 2
	state := &memoryTransparencyState{current: []SMTLeaf{{Key: key, LeafHash: leaf}}, history: [][]byte{makeTestHistoryEntry(1, key, leaf)}}
	sth := &memoryTransparencySTH{err: errors.New("no sth")}
	if _, err := NewTransparencyProofService(state, sth).CurrentStateProof(context.Background(), key); err == nil {
		t.Fatal("expected STH lookup failure")
	}
}

func TestCurrentStateProofNilService(t *testing.T) {
	if _, err := (*TransparencyProofService)(nil).CurrentStateProof(context.Background(), [32]byte{}); err == nil {
		t.Fatal("expected nil service error")
	}
}

func TestCurrentStateProofMatchesFrozenVectors(t *testing.T) {
	var smt smtVector
	var history historyVector
	readJSON(t, "transparency_smt_proofs.json", &smt)
	readJSON(t, "transparency_history_proofs.json", &history)
	if len(smt.Proofs) < 1 || len(history.Entries) < 9 {
		t.Fatal("frozen vectors do not contain the expected current-state fixtures")
	}

	current := make([]SMTLeaf, 0, 9)
	seen := make(map[[32]byte]struct{})
	// The 32-entry fixture is a publication history, not a snapshot. Some keys
	// are updated repeatedly, so the SMT current state is the latest publication
	// for each stable key, not the first nine history entries.
	for i := len(history.Entries) - 1; i >= 0; i-- {
		item := history.Entries[i]
		entry, err := ParseHistoryEntryV1(decodeBytes(t, item.EntryHex))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := seen[entry.SMTKey]; ok {
			continue
		}
		seen[entry.SMTKey] = struct{}{}
		current = append(current, SMTLeaf{Key: entry.SMTKey, LeafHash: entry.LeafHash})
	}
	if len(current) != 9 {
		t.Fatalf("reconstructed current-state leaf count = %d, want 9", len(current))
	}
	historyRaw := make([][]byte, len(history.Entries))
	for i, item := range history.Entries {
		historyRaw[i] = decodeBytes(t, item.EntryHex)
	}

	smtRoot := decode32(t, smt.RootHex)
	historyRoot := decode32(t, history.HistoryRootHex)
	key := decode32(t, smt.Proofs[0].LeafKeyHex)
	sth := &memoryTransparencySTH{
		sth: SignedTreeHeadV1{TreeSize: uint64(history.TreeSize), SMTRoot: smtRoot, HistoryRoot: historyRoot},
		raw: []byte{0x01},
	}
	state := &memoryTransparencyState{current: current, history: historyRaw}

	bundle, err := NewTransparencyProofService(state, sth).CurrentStateProof(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.SMTRoot != smtRoot || bundle.HistoryRoot != historyRoot {
		t.Fatal("proof service roots differ from frozen vectors")
	}
	if bundle.TreeSize != uint64(history.TreeSize) {
		t.Fatalf("tree size = %d, want %d", bundle.TreeSize, history.TreeSize)
	}
	if bundle.HistorySequence == 0 || bundle.HistoryIndex < 0 {
		t.Fatal("missing history publication metadata")
	}
}

func TestHistoryConsistencyProofBindsGeneratedProofToSTH(t *testing.T) {
	history := make([][]byte, 4)
	var key, leaf [32]byte
	for i := range history {
		key[31] = byte(i + 1)
		leaf[31] = byte(i + 10)
		history[i] = makeTestHistoryEntry(byte(i+1), key, leaf)
	}

	oldSize := uint64(2)
	oldRoot := HistoryRootV1(history[:int(oldSize)])
	newRoot := HistoryRootV1(history)
	state := &memoryTransparencyState{history: history}
	sth := &memoryTransparencySTH{
		sth: SignedTreeHeadV1{
			TreeSize:    uint64(len(history)),
			HistoryRoot: newRoot,
		},
		raw: []byte{0xbb},
	}

	bundle, err := NewTransparencyProofService(state, sth).HistoryConsistencyProof(context.Background(), oldSize)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.OldSize != oldSize || bundle.NewSize != uint64(len(history)) {
		t.Fatalf("unexpected bundle sizes: %+v", bundle)
	}
	if bundle.OldRoot != oldRoot || bundle.NewRoot != newRoot {
		t.Fatal("bundle roots do not match history roots")
	}
	if err := VerifyHistoryConsistencyV1(int(oldSize), len(history), bundle.OldRoot, bundle.NewRoot, bundle.Proof); err != nil {
		t.Fatalf("returned consistency proof does not verify: %v", err)
	}
	if string(bundle.SignedTreeHead) != string([]byte{0xbb}) {
		t.Fatal("STH bytes not retained")
	}
}

func TestHistoryConsistencyProofRejectsInvalidOldSize(t *testing.T) {
	history := [][]byte{
		makeTestHistoryEntry(1, [32]byte{1}, [32]byte{2}),
		makeTestHistoryEntry(2, [32]byte{3}, [32]byte{4}),
	}
	state := &memoryTransparencyState{history: history}
	sth := &memoryTransparencySTH{sth: SignedTreeHeadV1{
		TreeSize:    2,
		HistoryRoot: HistoryRootV1(history),
	}}
	service := NewTransparencyProofService(state, sth)

	for _, oldSize := range []uint64{0, 2, 3} {
		if _, err := service.HistoryConsistencyProof(context.Background(), oldSize); err == nil {
			t.Fatalf("old size %d unexpectedly accepted", oldSize)
		}
	}
}

func TestHistoryConsistencyProofRejectsSTHRootMismatch(t *testing.T) {
	history := [][]byte{
		makeTestHistoryEntry(1, [32]byte{1}, [32]byte{2}),
		makeTestHistoryEntry(2, [32]byte{3}, [32]byte{4}),
	}
	state := &memoryTransparencyState{history: history}
	sth := &memoryTransparencySTH{
		sth: SignedTreeHeadV1{
			TreeSize: 2,
		},
	}
	if _, err := NewTransparencyProofService(state, sth).HistoryConsistencyProof(context.Background(), 1); err == nil {
		t.Fatal("expected STH root mismatch")
	}
}

func TestHistoryConsistencyProofPropagatesSTHReadFailure(t *testing.T) {
	history := [][]byte{
		makeTestHistoryEntry(1, [32]byte{1}, [32]byte{2}),
		makeTestHistoryEntry(2, [32]byte{3}, [32]byte{4}),
	}
	state := &memoryTransparencyState{history: history}
	sth := &memoryTransparencySTH{err: errors.New("no sth")}
	if _, err := NewTransparencyProofService(state, sth).HistoryConsistencyProof(context.Background(), 1); err == nil {
		t.Fatal("expected STH lookup failure")
	}
}
