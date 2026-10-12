package kt

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func TestParseSignedTreeHeadV1(t *testing.T) {
	const sthHex = "a701010218200358203dafdf96b666095d1bf10a1433fb366fe4feb3fa3df51a4d7a6c891074053daa0458207e506ec5003b6011dc444a13ec4bedbefbb920ffc8e460ccf65d8233dd89f7e7051a655577a00658209a1c5dde77c2131a38a5f7c5d4ce575531bd874bf467516160bb2d215c795f0407584096ae97746c8793fd1f8927c3f891465d3476e1bdb91d7919c8540bddbccc0d3149c355facdb16a36d75ae2b332764935b33a989ffd3b090ddad74cb3c84ab80d"
	sth, err := ParseSignedTreeHeadV1(mustHex(t, sthHex))
	if err != nil {
		t.Fatal(err)
	}
	if sth.TreeSize != 32 || sth.IssuedAt != 1700100000 {
		t.Fatalf("unexpected STH metadata: tree_size=%d issued_at=%d", sth.TreeSize, sth.IssuedAt)
	}
	wantDigest := mustHex(t, "96ab2b13b3815251a80e57055dbf952ec7701fac3ffbc2416b9b20083b5d4388")
	if string(sth.STHDigest[:]) != string(wantDigest) {
		t.Fatalf("unexpected STH digest: got %x want %x", sth.STHDigest, wantDigest)
	}
}

func TestRejectsUnknownAndWrongFieldShapes(t *testing.T) {
	const validSTH = "a701010218200358203dafdf96b666095d1bf10a1433fb366fe4feb3fa3df51a4d7a6c891074053daa0458207e506ec5003b6011dc444a13ec4bedbefbb920ffc8e460ccf65d8233dd89f7e7051a655577a00658209a1c5dde77c2131a38a5f7c5d4ce575531bd874bf467516160bb2d215c795f0407584096ae97746c8793fd1f8927c3f891465d3476e1bdb91d7919c8540bddbccc0d3149c355facdb16a36d75ae2b332764935b33a989ffd3b090ddad74cb3c84ab80d"
	raw := mustHex(t, validSTH)
	raw = append(raw, 0x00) // valid first item followed by trailing data; strict decoder must reject.
	if _, err := ParseSignedTreeHeadV1(raw); err == nil {
		t.Fatal("trailing bytes accepted")
	}
}

func TestParsesEquivocationEvidenceVector(t *testing.T) {
	const path = "../../../../test-vectors/v1/transparency_equivocation.json"
	data, err := os.ReadFile(filepath.FromSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	const marker = `"equivocation_evidence_hex": "`
	start := indexOf(data, []byte(marker))
	if start < 0 {
		t.Fatal("equivocation evidence marker not found")
	}
	start += len(marker)
	end := indexOf(data[start:], []byte(`"`))
	if end < 0 {
		t.Fatal("equivocation evidence value not terminated")
	}
	rawHex := data[start : start+end]
	evidence, err := ParseEquivocationEvidenceV1(mustHex(t, string(rawHex)))
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.WitnessStatements) != 2 {
		t.Fatalf("witness statements: got %d want 2", len(evidence.WitnessStatements))
	}
}

func TestParsesFrozenLeafAndHistoryEntry(t *testing.T) {
	const leafHex = "a9015000112233445566778899aabbccddeeff02010350010101010101010101010101010101010458207776e870b93354f2a0b24c23f2a36cc4e80e223218c1b97926fdd018396a2b9b055820b39af3676aac20db81c831af4b077b61240ac157b872108b46acb1c19c6f6265065840ea15fdcea10d6c22a057c1d7b6a5860f6eb4594af62e6cd695ffa9118a53a38b9d78358808c79ca2fccee0c05443737fe8e9007371b85597ddf8a05fc71f22090758207d6698f2aa51b0812025628dcaa91913f5a387b6a368bafe0fef456715056bba085820818f3cbb2ac8a4d924a8fbb0e7777f0ec7a53e27e8903ae283cd51d6a0888e54095840b73b192f111d853c72137c4bcc784c237b616aa84b5baf025612ffac444e022f19b3d903344a7b2a10661fb6ecefd8934a2241918b7105af32dd4423f1c7b002"
	leaf, err := ParseTransparencyLeafV1(mustHex(t, leafHex))
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Epoch != 1 || leaf.AccountID != [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff} {
		t.Fatalf("unexpected leaf metadata: epoch=%d account_id=%x", leaf.Epoch, leaf.AccountID)
	}

	const historyHex = "a301010258201736c25ed30fb80ee6e289313a7981203b9b080c78a2357984304d83fe1ce96803582028a65a37a972035ef3256acfdb23a9824cfa9cb00ff8543dcea953f9c2c87907"
	entry, err := ParseHistoryEntryV1(mustHex(t, historyHex))
	if err != nil {
		t.Fatal(err)
	}
	if entry.Sequence != 1 {
		t.Fatalf("unexpected history sequence: %d", entry.Sequence)
	}
}

func TestParsesFrozenWitnessStatement(t *testing.T) {
	const witnessHex = "a601010250010101010101010101010101010101010358209a1c5dde77c2131a38a5f7c5d4ce575531bd874bf467516160bb2d215c795f0404182005582096ab2b13b3815251a80e57055dbf952ec7701fac3ffbc2416b9b20083b5d4388065840d51046b36c4fdf66d30ee4a5353a67183a23e64421cdc4db3013fb9919c2a3991d9b51dcbb2903afb33d46f2eca22a15a714eaf21bac143a4dadfa69192ce604"
	statement, err := ParseWitnessStatementV1(mustHex(t, witnessHex))
	if err != nil {
		t.Fatal(err)
	}
	if statement.TreeSize != 32 || statement.WitnessID != [16]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1} {
		t.Fatalf("unexpected witness statement metadata: tree_size=%d witness_id=%x", statement.TreeSize, statement.WitnessID)
	}
}

func indexOf(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
