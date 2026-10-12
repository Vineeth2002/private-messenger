package kt

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func mustVerifyHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyFrozenLeafAndSMTKey(t *testing.T) {
	const leafHex = "a9015000112233445566778899aabbccddeeff02010350010101010101010101010101010101010458207776e870b93354f2a0b24c23f2a36cc4e80e223218c1b97926fdd018396a2b9b055820b39af3676aac20db81c831af4b077b61240ac157b872108b46acb1c19c6f6265065840ea15fdcea10d6c22a057c1d7b6a5860f6eb4594af62e6cd695ffa9118a53a38b9d78358808c79ca2fccee0c05443737fe8e9007371b85597ddf8a05fc71f22090758207d6698f2aa51b0812025628dcaa91913f5a387b6a368bafe0fef456715056bba085820818f3cbb2ac8a4d924a8fbb0e7777f0ec7a53e27e8903ae283cd51d6a0888e54095840b73b192f111d853c72137c4bcc784c237b616aa84b5baf025612ffac444e022f19b3d903344a7b2a10661fb6ecefd8934a2241918b7105af32dd4423f1c7b002"
	leaf, leafHash, err := VerifyTransparencyLeafV1(mustVerifyHex(t, leafHex))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(leafHash[:]); got != "a7fcac2d4836cdf2c4c77e3b43212c09e0a3dddb9a3d77ad017ece26074491e0" {
		t.Fatalf("leaf hash %s", got)
	}

	key := SMTKey(leaf.AccountID, leaf.DeviceID)
	if got := hex.EncodeToString(key[:]); got != "1736c25ed30fb80ee6e289313a7981203b9b080c78a2357984304d83fe1ce968" {
		t.Fatalf("SMT key %s", got)
	}

	tampered := mustVerifyHex(t, leafHex)
	tampered[len(tampered)-1] ^= 0x01
	if _, _, err := VerifyTransparencyLeafV1(tampered); err == nil {
		t.Fatal("tampered leaf accepted")
	}
}

type equivocationVector struct {
	Log struct {
		PublicKeyHex string `json:"public_key_hex"`
	} `json:"log"`
	STHAHex         string `json:"sth_a_hex"`
	STHBHex         string `json:"sth_b_hex"`
	WitnessRegistry []struct {
		WitnessIDHex string `json:"witness_id_hex"`
		PublicKeyHex string `json:"public_key_hex"`
		StatementHex string `json:"statement_hex"`
	} `json:"witness_registry"`
}

func loadEquivocationVector(t *testing.T) equivocationVector {
	t.Helper()
	path := filepath.FromSlash("../../../../test-vectors/v1/transparency_equivocation.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v equivocationVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func mustFixed32(t *testing.T, hexValue string) [32]byte {
	t.Helper()
	var out [32]byte
	data := mustVerifyHex(t, hexValue)
	if len(data) != len(out) {
		t.Fatalf("want 32 bytes, got %d", len(data))
	}
	copy(out[:], data)
	return out
}

func mustFixed16(t *testing.T, hexValue string) [16]byte {
	t.Helper()
	var out [16]byte
	data := mustVerifyHex(t, hexValue)
	if len(data) != len(out) {
		t.Fatalf("want 16 bytes, got %d", len(data))
	}
	copy(out[:], data)
	return out
}

func TestVerifyFrozenSTHAndWitnessVectors(t *testing.T) {
	v := loadEquivocationVector(t)
	logPublic := mustFixed32(t, v.Log.PublicKeyHex)

	sthA, err := VerifySignedTreeHeadV1(mustVerifyHex(t, v.STHAHex), logPublic)
	if err != nil {
		t.Fatal(err)
	}
	sthB, err := VerifySignedTreeHeadV1(mustVerifyHex(t, v.STHBHex), logPublic)
	if err != nil {
		t.Fatal(err)
	}
	if !IsSTHEquivocation(sthA, sthB) {
		t.Fatal("expected same-size STH equivocation")
	}

	registry := make(map[[16]byte][32]byte, len(v.WitnessRegistry))
	statements := make([]WitnessStatementV1, 0, len(v.WitnessRegistry))
	for _, entry := range v.WitnessRegistry {
		id := mustFixed16(t, entry.WitnessIDHex)
		registry[id] = mustFixed32(t, entry.PublicKeyHex)

		statement, err := VerifyWitnessStatementV1(mustVerifyHex(t, entry.StatementHex), registry)
		if err != nil {
			t.Fatal(err)
		}
		statements = append(statements, statement)
	}

	if !WitnessConflictExists(statements) {
		t.Fatal("expected conflicting witness statements")
	}
	if got := WitnessQuorumCount(statements, sthA); got != 2 {
		t.Fatalf("STH A quorum count = %d, want 2", got)
	}
	if got := WitnessQuorumCount(statements, sthB); got != 1 {
		t.Fatalf("STH B quorum count = %d, want 1", got)
	}

	tamperedSTH := mustVerifyHex(t, v.STHAHex)
	tamperedSTH[len(tamperedSTH)-1] ^= 0x01
	if _, err := VerifySignedTreeHeadV1(tamperedSTH, logPublic); err == nil {
		t.Fatal("tampered STH accepted")
	}

	tamperedWitness := mustVerifyHex(t, v.WitnessRegistry[0].StatementHex)
	tamperedWitness[len(tamperedWitness)-1] ^= 0x01
	if _, err := VerifyWitnessStatementV1(tamperedWitness, registry); err == nil {
		t.Fatal("tampered witness statement accepted")
	}
}
