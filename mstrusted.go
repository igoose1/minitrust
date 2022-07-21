package mstrusted

import (
	"bytes"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"aead.dev/minisign"
)

func getTrustedPath() string {
	dirname, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	return filepath.Join(dirname, ".minisign/trusted")
}

func ensureTrustedDir() error {
	err := os.MkdirAll(getTrustedPath(), 0700)
	if !os.IsExist(err) {
		return err
	}
	return nil
}

func extractID(s minisign.Signature) string {
	return strings.ToUpper(strconv.FormatUint(s.KeyID, 16))
}

// readPubKey reads from keyPath and returns public key and untrusted comment.
func readPubKey(keyPath string) (minisign.PublicKey, string, error) {
	content, err := ioutil.ReadFile(keyPath)
	if os.IsNotExist(err) {
		return minisign.PublicKey{}, "", errors.New("mstrusted: public key doesn't exist.")
	} else if err != nil {
		return minisign.PublicKey{}, "", errors.New("mstrusted: public key is unreadable.")
	}

	var (
		key     minisign.PublicKey
		comment string = ""
	)

	const prefix = "untrusted comment: "
	if strings.HasPrefix(string(content), prefix) {
		commentLine := string(bytes.SplitN(content, []byte{'\n'}, 2)[0])
		comment = commentLine[len(prefix):]
	}

	if err = key.UnmarshalText(content); err != nil {
		return minisign.PublicKey{}, "", err
	}
	return key, comment, nil
}

// SearchTrustedPubKey returns base64 of public key, untrusted comment and error if raised.
func SearchTrustedPubKey(sigFile string) (string, string, error) {
	if err := ensureTrustedDir(); err != nil {
		return "", "", errors.New("mstrusted: can't create trusted directory.")
	}

	signature, err := minisign.SignatureFromFile(sigFile)
	if err != nil {
		return "", "", err
	}

	keyPath := filepath.Join(getTrustedPath(), extractID(signature)+".pub")
	key, comment, err := readPubKey(keyPath)
	if err != nil {
		return "", "", err
	}

	return key.String(), comment, nil
}
