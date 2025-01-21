// Copyright 2025 Oskar Sharipov
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package minitrust

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	rawPubKey = "RWRWfuqg9DPmJzteqVmj5xSm7z1V0ZTNA66UGpF+5vdkUe8llEMWkC6n"
	pubKeyID  = "27E633F4A0EA7E56"
)

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
		if err := b.EnsureTrustedDir(); err != nil {
			t.Fatal(err)
		}
		_, err := os.Stat(test)
		if err != nil {
			t.Fatal(err)
		}
	}
}
