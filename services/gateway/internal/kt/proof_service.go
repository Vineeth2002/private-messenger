package kt

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type TransparencyStateReader interface {
	CurrentState(ctx context.Context) ([]SMTLeaf, error)
	HistoryEntries(ctx context.Context) ([][]byte, error)
}

type TransparencySTHReader interface {
	Latest(ctx context.Context) (SignedTreeHeadV1, []byte, time.Time, error)
}

// CurrentStateProofBundle is an internal service result. It is not a new wire
// format; callers must expose the existing frozen PM-CBOR objects separately.
type CurrentStateProofBundle struct {
	SMTKey          [32]byte
	LeafHash        [32]byte
	SMTRoot         [32]byte
	SMTSiblings     [][32]byte
	HistorySequence uint64
	HistoryRoot     [32]byte
	HistoryIndex    int
	HistoryEntry    []byte
	HistoryProof    [][32]byte
	SignedTreeHead  []byte
	TreeSize        uint64
}

type TransparencyProofService struct {
	state TransparencyStateReader
	sth   TransparencySTHReader
}

// HistoryConsistencyProofBundle is an internal service result. It is not a
// new wire format; callers must expose the existing frozen PM-CBOR objects
// separately.
type HistoryConsistencyProofBundle struct {
	OldSize        uint64
	NewSize        uint64
	OldRoot        [32]byte
	NewRoot        [32]byte
	Proof          [][32]byte
	SignedTreeHead []byte
}

func NewTransparencyProofService(state TransparencyStateReader, sth TransparencySTHReader) *TransparencyProofService {
	return &TransparencyProofService{state: state, sth: sth}
}

func (s *TransparencyProofService) CurrentStateProof(ctx context.Context, targetKey [32]byte) (CurrentStateProofBundle, error) {
	if s == nil || s.state == nil || s.sth == nil {
		return CurrentStateProofBundle{}, errors.New("nil transparency proof service")
	}

	current, err := s.state.CurrentState(ctx)
	if err != nil {
		return CurrentStateProofBundle{}, err
	}

	var target SMTLeaf
	found := false
	for _, leaf := range current {
		if leaf.Key != targetKey {
			continue
		}
		if found {
			return CurrentStateProofBundle{}, errors.New("duplicate current-state key")
		}
		target = leaf
		found = true
	}
	if !found {
		return CurrentStateProofBundle{}, ErrTransparencyStateNotFound
	}

	smtRoot, smtProof, err := SMTInclusionProofV1(current, targetKey)
	if err != nil {
		return CurrentStateProofBundle{}, err
	}
	if err := VerifySMTInclusionV1(target.Key, target.LeafHash, smtProof, smtRoot); err != nil {
		return CurrentStateProofBundle{}, fmt.Errorf("generated SMT proof failed self-check: %w", err)
	}

	history, err := s.state.HistoryEntries(ctx)
	if err != nil {
		return CurrentStateProofBundle{}, err
	}

	index := -1
	var sequence uint64
	var entryBytes []byte
	for i := len(history) - 1; i >= 0; i-- {
		entry, err := ParseHistoryEntryV1(history[i])
		if err != nil {
			return CurrentStateProofBundle{}, fmt.Errorf("invalid history entry %d: %w", i+1, err)
		}
		if entry.SMTKey == target.Key && entry.LeafHash == target.LeafHash {
			index = i
			sequence = entry.Sequence
			entryBytes = append([]byte(nil), history[i]...)
			break
		}
	}
	if index < 0 {
		return CurrentStateProofBundle{}, errors.New("current state has no matching history publication")
	}

	historyRoot := HistoryRootV1(history)
	historyProof, err := HistoryInclusionProofV1(history, index)
	if err != nil {
		return CurrentStateProofBundle{}, err
	}
	if err := VerifyHistoryInclusionV1(entryBytes, index, len(history), historyProof, historyRoot); err != nil {
		return CurrentStateProofBundle{}, fmt.Errorf("generated history proof failed self-check: %w", err)
	}

	sth, sthRaw, _, err := s.sth.Latest(ctx)
	if err != nil {
		return CurrentStateProofBundle{}, err
	}
	if sth.TreeSize != uint64(len(history)) {
		return CurrentStateProofBundle{}, errors.New("persisted STH tree size does not match history state")
	}
	if sth.SMTRoot != smtRoot {
		return CurrentStateProofBundle{}, errors.New("persisted STH SMT root does not match current state")
	}
	if sth.HistoryRoot != historyRoot {
		return CurrentStateProofBundle{}, errors.New("persisted STH history root does not match history state")
	}

	return CurrentStateProofBundle{
		SMTKey:          target.Key,
		LeafHash:        target.LeafHash,
		SMTRoot:         smtRoot,
		SMTSiblings:     smtProof,
		HistorySequence: sequence,
		HistoryRoot:     historyRoot,
		HistoryIndex:    index,
		HistoryEntry:    entryBytes,
		HistoryProof:    historyProof,
		SignedTreeHead:  append([]byte(nil), sthRaw...),
		TreeSize:        sth.TreeSize,
	}, nil
}

// HistoryConsistencyProof returns the frozen RFC 6962 consistency proof from
// the persisted history prefix at oldSize to the current published history.
// It self-verifies the generated proof and binds the new root and tree size
// to the latest persisted STH.
func (s *TransparencyProofService) HistoryConsistencyProof(ctx context.Context, oldSize uint64) (HistoryConsistencyProofBundle, error) {
	if s == nil || s.state == nil || s.sth == nil {
		return HistoryConsistencyProofBundle{}, errors.New("nil transparency proof service")
	}
	if oldSize == 0 {
		return HistoryConsistencyProofBundle{}, errors.New("invalid old history size")
	}

	history, err := s.state.HistoryEntries(ctx)
	if err != nil {
		return HistoryConsistencyProofBundle{}, err
	}
	newSize := uint64(len(history))
	if oldSize >= newSize {
		return HistoryConsistencyProofBundle{}, errors.New("invalid history consistency sizes")
	}

	oldRoot := HistoryRootV1(history[:int(oldSize)])
	newRoot := HistoryRootV1(history)
	proof, err := HistoryConsistencyProofV1(history, int(oldSize))
	if err != nil {
		return HistoryConsistencyProofBundle{}, err
	}

	if err := VerifyHistoryConsistencyV1(int(oldSize), int(newSize), oldRoot, newRoot, proof); err != nil {
		return HistoryConsistencyProofBundle{}, fmt.Errorf("generated history consistency proof failed self-check: %w", err)
	}

	sth, sthRaw, _, err := s.sth.Latest(ctx)
	if err != nil {
		return HistoryConsistencyProofBundle{}, err
	}
	if sth.TreeSize != newSize {
		return HistoryConsistencyProofBundle{}, errors.New("persisted STH tree size does not match history state")
	}
	if sth.HistoryRoot != newRoot {
		return HistoryConsistencyProofBundle{}, errors.New("persisted STH history root does not match history state")
	}

	return HistoryConsistencyProofBundle{
		OldSize:        oldSize,
		NewSize:        newSize,
		OldRoot:        oldRoot,
		NewRoot:        newRoot,
		Proof:          proof,
		SignedTreeHead: append([]byte(nil), sthRaw...),
	}, nil
}
