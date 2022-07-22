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
