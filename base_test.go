package minitrust

import (
	"os"
	"path/filepath"
	"testing"
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
		filepath.Join(dir, "exists"),
		filepath.Join(dir, "exists"),
	} {
		b := New(test)
		if err := b.ensureTrustedDir(); err != nil {
			t.Fatal(err)
		}
		_, err := os.Stat(test)
		if err != nil {
			t.Fatal(err)
		}
	}
}
