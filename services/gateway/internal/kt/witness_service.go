package kt

import (
	"errors"
	"fmt"
)

type WitnessSecurityState uint8

const (
	WitnessStateVerified WitnessSecurityState = iota + 1
	WitnessStateDegraded
	WitnessStateSecurityFailure
)

var (
	ErrInvalidWitnessRegistry = errors.New("invalid witness registry")
	ErrWitnessQuorumConflict  = errors.New("conflicting valid witness statements")
)

const (
	ConfiguredWitnessCount = 3
	WitnessQuorumThreshold = 2
)

type WitnessVerifier struct {
	registry map[[16]byte][32]byte
}

type WitnessVerificationResult struct {
	State         WitnessSecurityState
	Statements    []WitnessStatementV1
	AgreeingCount int
}

func NewWitnessVerifier(registry map[[16]byte][32]byte) (*WitnessVerifier, error) {
	if len(registry) != ConfiguredWitnessCount {
		return nil, fmt.Errorf(
			"%w: got %d witnesses, want %d",
			ErrInvalidWitnessRegistry,
			len(registry),
			ConfiguredWitnessCount,
		)
	}

	copied := make(map[[16]byte][32]byte, len(registry))
	for id, public := range registry {
		copied[id] = public
	}

	return &WitnessVerifier{registry: copied}, nil
}

func (v *WitnessVerifier) Verify(
	sth SignedTreeHeadV1,
	statementsRaw [][]byte,
) (WitnessVerificationResult, error) {
	if v == nil || len(v.registry) != ConfiguredWitnessCount {
		return WitnessVerificationResult{}, ErrInvalidWitnessRegistry
	}

	result := WitnessVerificationResult{
		State:      WitnessStateDegraded,
		Statements: make([]WitnessStatementV1, 0, len(statementsRaw)),
	}

	for _, raw := range statementsRaw {
		statement, err := VerifyWitnessStatementV1(raw, v.registry)
		if err != nil {
			result.State = WitnessStateSecurityFailure
			return result, fmt.Errorf("witness verification failed: %w", err)
		}

		if statement.LogID != sth.LogID || statement.TreeSize != sth.TreeSize {
			continue
		}

		// Retain every valid statement here. Conflict detection must see
		// repeated statements from the same witness as well as statements
		// from different witnesses. Quorum counting deduplicates witness IDs
		// separately in WitnessQuorumCount.
		result.Statements = append(result.Statements, statement)
	}

	if WitnessConflictExists(result.Statements) {
		result.State = WitnessStateSecurityFailure
		return result, ErrWitnessQuorumConflict
	}

	result.AgreeingCount = WitnessQuorumCount(result.Statements, sth)
	if result.AgreeingCount >= WitnessQuorumThreshold {
		result.State = WitnessStateVerified
	} else {
		result.State = WitnessStateDegraded
	}

	return result, nil
}
