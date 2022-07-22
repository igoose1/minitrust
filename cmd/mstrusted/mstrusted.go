package main

import (
	"flag"
	"log"

	"github.com/jedisct1/go-minisign"
	"oskarsh.ru/mstrusted"
)

func main() {
	var (
		//	hashFlag   bool
		sigFile    string
		outputFlag bool
		file       string
	)
	// flag.BoolVar(&hashFlag, "H", false, "require input to be prehashed.")
	flag.StringVar(&sigFile, "x", "", "signature file (default: <file>.minisig)")
	flag.BoolVar(&outputFlag, "o", false, "output the file content after verification")
	flag.StringVar(&file, "m", "", "file to verify.")
	flag.Parse()

	if sigFile == "" {
		sigFile = file + ".minisig"
	}

	pubKey, comment, err := mstrusted.SearchTrustedPubKey(sigFile)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	log.Printf("Verifying with %v (%v)\n", comment, mstrusted.EncodeID(pubKey.KeyId))
	_, err = verify(pubKey, file, sigFile)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	log.Printf("Signature and comment signature verified.")
}

func verify(key minisign.PublicKey, file string, sigFile string) (bool, error) {
	s, err := minisign.NewSignatureFromFile(sigFile)
	if err != nil {
		return false, err
	}
	return key.VerifyFromFile(file, s)
}
