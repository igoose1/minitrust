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
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/jedisct1/go-minisign"
)

const (
	trustedDirPerm = 0o700
	trustedKeyPerm = 0o600
)

type Base struct {
	trustedDir string
}

func New(trustedDir string) Base {
	return Base{trustedDir: trustedDir}
}

func (b *Base) EnsureTrustedDir() error {
	err := os.MkdirAll(b.trustedDir, trustedDirPerm)
	if err != nil && !os.IsExist(err) {
		return err
	}
	return nil
}

func (b *Base) getKeyPath(keyID [8]byte) string {
	return filepath.Join(b.trustedDir, EncodeID(keyID)+".pub")
}

// SearchTrustedPubKey returns public key and untrusted comment.
func (b *Base) SearchTrustedPubKey(sigFile string) (minisign.PublicKey, string, error) {
	if err := b.EnsureTrustedDir(); err != nil {
		return minisign.PublicKey{}, "", errors.New("minitrust: can't create trusted directory.")
	}

	signature, err := minisign.NewSignatureFromFile(sigFile)
	if err != nil {
		return minisign.PublicKey{}, "", err
	}

	key, comment, err := ReadKeyFile(b.getKeyPath(signature.KeyId))
	if err != nil {
		return minisign.PublicKey{}, "", err
	}

	return key, comment, nil
}

func (b *Base) AddTrustedPubKey(rawPubKey, comment string) error {
	if err := b.EnsureTrustedDir(); err != nil {
		return errors.New("minitrust: can't create trusted directory.")
	}
	if strings.Count(comment, "\n") != 0 {
		return errors.New("minitrust: comment must be one-lined.")
	}

	pk, err := minisign.NewPublicKey(rawPubKey)
	if err != nil {
		return err
	}

	content := commentPrefix + comment + "\n" + EncodePublicKey(pk)
	return os.WriteFile(b.getKeyPath(pk.KeyId), []byte(content), trustedKeyPerm)
}
