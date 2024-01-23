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
