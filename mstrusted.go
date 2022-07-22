package mstrusted

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jedisct1/go-minisign"
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

func EncodePublicKey(pk minisign.PublicKey) string {
	var bin [42]byte
	copy(bin[:2], pk.SignatureAlgorithm[:])
	copy(bin[2:10], pk.KeyId[:])
	copy(bin[10:42], pk.PublicKey[:])
	return base64.StdEncoding.EncodeToString(bin[:])
}

func EncodeID(keyId [8]byte) string {
	le64ID := binary.LittleEndian.Uint64(keyId[:])
	return strings.ToUpper(strconv.FormatUint(le64ID, 16))
}

func decodeKeyFileContent(in string) (minisign.PublicKey, string, error) {
	const prefix = "untrusted comment: "
	lines := strings.SplitN(in, "\n", 2)
	if len(lines) < 2 || !strings.HasPrefix(lines[0], prefix) {
		return minisign.PublicKey{}, "", errors.New("mstrusted: incomplete encoded public key.")
	}
	comment := lines[0][len(prefix):]
	key, err := minisign.NewPublicKey(lines[1])
	if err != nil {
		return minisign.PublicKey{}, "", err
	}
	return key, comment, nil
}

// readKeyFile reads from keyPath and returns public key with untrusted comment.
func readKeyFile(keyPath string) (minisign.PublicKey, string, error) {
	content, err := ioutil.ReadFile(keyPath)
	if os.IsNotExist(err) {
		return minisign.PublicKey{}, "", errors.New("mstrusted: public key doesn't exist in trusted directory.")
	} else if err != nil {
		return minisign.PublicKey{}, "", err
	}
	return decodeKeyFileContent(string(content))
}

// SearchTrustedPubKey returns public key and untrusted comment.
func SearchTrustedPubKey(sigFile string) (minisign.PublicKey, string, error) {
	if err := ensureTrustedDir(); err != nil {
		return minisign.PublicKey{}, "", errors.New("mstrusted: can't create trusted directory.")
	}

	signature, err := minisign.NewSignatureFromFile(sigFile)
	if err != nil {
		return minisign.PublicKey{}, "", err
	}

	keyPath := filepath.Join(getTrustedPath(), EncodeID(signature.KeyId)+".pub")
	key, comment, err := readKeyFile(keyPath)
	if err != nil {
		return minisign.PublicKey{}, "", err
	}

	return key, comment, nil
}