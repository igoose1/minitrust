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
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/jedisct1/go-minisign"
)

const commentPrefix = "untrusted comment: "

// EncodePublicKey returns base64-coded public key.
func EncodePublicKey(pk minisign.PublicKey) string {
	var bin [42]byte
	copy(bin[:2], pk.SignatureAlgorithm[:])
	copy(bin[2:10], pk.KeyId[:])
	copy(bin[10:42], pk.PublicKey[:])
	return base64.StdEncoding.EncodeToString(bin[:])
}

// EncodeID returns hex-coded public key ID.
func EncodeID(keyId [8]byte) string {
	le64ID := binary.LittleEndian.Uint64(keyId[:])
	return strings.ToUpper(strconv.FormatUint(le64ID, 16))
}

// DecodeKeyFileContent parses `in` and returns PublicKey and untrusted comment.
func DecodeKeyFileContent(in string) (minisign.PublicKey, string, error) {
	lines := strings.SplitN(in, "\n", 2)
	if len(lines) < 2 || !strings.HasPrefix(lines[0], commentPrefix) {
		return minisign.PublicKey{}, "", errors.New("minitrust: incomplete encoded public key.")
	}
	comment := lines[0][len(commentPrefix):]
	key, err := minisign.NewPublicKey(lines[1])
	if err != nil {
		return minisign.PublicKey{}, "", err
	}
	return key, comment, nil
}

// ReadKeyFile reads from keyPath and returns public key with untrusted comment.
func ReadKeyFile(keyPath string) (minisign.PublicKey, string, error) {
	content, err := os.ReadFile(keyPath)
	if os.IsNotExist(err) {
		return minisign.PublicKey{}, "", errors.New("minitrust: public key doesn't exist in trusted directory.")
	} else if err != nil {
		return minisign.PublicKey{}, "", err
	}
	return DecodeKeyFileContent(string(content))
}
