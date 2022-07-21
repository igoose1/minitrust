package mstrusted

import (
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

func readPubKey(keyPath string) (minisign.PublicKey, error) {
	bytes, err := ioutil.ReadFile(keyPath)
	if os.IsNotExist(err) {
		return minisign.PublicKey{}, errors.New("mstrusted: public key doesn't exist.")
	} else if err != nil {
		return minisign.PublicKey{}, errors.New("mstrusted: public key is unreadable.")
	}
	var key minisign.PublicKey
	if err = key.UnmarshalText(bytes); err != nil {
		return minisign.PublicKey{}, err
	}
	return key, nil
}

func SearchTrustedPubKey(sigFile string) (string, error) {
	if err := ensureTrustedDir(); err != nil {
		return "", errors.New("mstrusted: can't create trusted directory.")
	}

	signature, err := minisign.SignatureFromFile(sigFile)
	if err != nil {
		return "", err
	}

	keyPath := filepath.Join(getTrustedPath(), extractID(signature)+".pub")
	key, err := readPubKey(keyPath)
	if err != nil {
		return "", err
	}

	return key.String(), nil
}
