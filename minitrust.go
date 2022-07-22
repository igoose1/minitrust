package minitrust

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

var logger = log.New(os.Stderr, "", log.Lshortfile)

const commentPrefix = "untrusted comment: "
const (
	trustedDirPerm = 0700
	trustedKeyPerm = 0600
)

func getTrustedPath() string {
	dirname, err := os.UserHomeDir()
	if err != nil {
		logger.Fatal(err)
	}
	return filepath.Join(dirname, ".minisign/trusted")
}

func ensureTrustedDir() error {
	err := os.MkdirAll(getTrustedPath(), trustedDirPerm)
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

// readKeyFile reads from keyPath and returns public key with untrusted comment.
func readKeyFile(keyPath string) (minisign.PublicKey, string, error) {
	content, err := ioutil.ReadFile(keyPath)
	if os.IsNotExist(err) {
		return minisign.PublicKey{}, "", errors.New("minitrust: public key doesn't exist in trusted directory.")
	} else if err != nil {
		return minisign.PublicKey{}, "", err
	}
	return decodeKeyFileContent(string(content))
}

func getKeyPath(keyID [8]byte) string {
	return filepath.Join(getTrustedPath(), EncodeID(keyID)+".pub")
}

// SearchTrustedPubKey returns public key and untrusted comment.
func SearchTrustedPubKey(sigFile string) (minisign.PublicKey, string, error) {
	if err := ensureTrustedDir(); err != nil {
		return minisign.PublicKey{}, "", errors.New("minitrust: can't create trusted directory.")
	}

	signature, err := minisign.NewSignatureFromFile(sigFile)
	if err != nil {
		return minisign.PublicKey{}, "", err
	}

	key, comment, err := readKeyFile(getKeyPath(signature.KeyId))
	if err != nil {
		return minisign.PublicKey{}, "", err
	}

	return key, comment, nil
}

func AddTrustedPubKey(rawPubKey string, comment string) error {
	if strings.Count(comment, "\n") != 0 {
		return errors.New("minitrust: comment must be one-lined.")
	}

	pk, err := minisign.NewPublicKey(rawPubKey)
	if err != nil {
		return err
	}

	content := strings.Join(
		[]string{
			commentPrefix + comment,
			EncodePublicKey(pk),
		},
		"\n",
	)
	return ioutil.WriteFile(getKeyPath(pk.KeyId), []byte(content), trustedKeyPerm)
}
