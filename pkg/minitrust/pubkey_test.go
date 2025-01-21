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
	"testing"

	"github.com/jedisct1/go-minisign"
)

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
