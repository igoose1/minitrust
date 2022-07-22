package minitrust

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jedisct1/go-minisign"
)

const rawPubKey = "RWRWfuqg9DPmJzteqVmj5xSm7z1V0ZTNA66UGpF+5vdkUe8llEMWkC6n"
const pubKeyID = "27E633F4A0EA7E56"

func mkdirTempHome(t *testing.T) string {
	dir, err := os.MkdirTemp("", "test-minitrust-*")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestEnsureTrustedDir(t *testing.T) {
	dir := mkdirTempHome(t)
	defer os.RemoveAll(dir)

	for _, test := range []string{
		dir,
		filepath.Join(dir, "whataboutthis"),
		filepath.Join(dir, "foo", "bar"),
	} {
		err := ensureTrustedDir(test)
		if err != nil {
			t.Fatal(err)
		}
		_, err = os.Stat(test)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestEncodePublicKey(t *testing.T) {
	pk, err := minisign.NewPublicKey(rawPubKey)
	if err != nil {
		t.Fatal(err)
	}
	got := EncodePublicKey(pk)
	if got != rawPubKey {
		t.Fatalf("encoded string doesn't match: got %v, expected %v.", got, rawPubKey)
	}
}

func TestEncodeID(t *testing.T) {
	pk, err := minisign.NewPublicKey(rawPubKey)
	if err != nil {
		t.Fatal(err)
	}
	got := EncodeID(pk.KeyId)
	if got != pubKeyID {
		t.Fatalf("encoded ID doesn't match: got %v, expected %v.", got, pubKeyID)
	}
}
