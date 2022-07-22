package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/jedisct1/go-minisign"
	"oskarsh.ru/mstrusted"
)

func main() {
	var (
		//	hashFlag   bool
		sigFile    string
		outputFlag bool
		file       string
		pubKey     string
		comment    string
	)
	verifyCommand := flag.NewFlagSet("-V", flag.ExitOnError)
	// flag.BoolVar(&hashFlag, "H", false, "require input to be prehashed.")
	verifyCommand.StringVar(&sigFile, "x", "", "signature file (default: <file>.minisig)")
	verifyCommand.BoolVar(&outputFlag, "o", false, "output the file content after verification")
	verifyCommand.StringVar(&file, "m", "", "file to verify.")

	addCommand := flag.NewFlagSet("-A", flag.ExitOnError)
	addCommand.StringVar(&pubKey, "P", "", "public key, as a base64 string.")
	addCommand.StringVar(&comment, "c", "", "add a one-line untrusted comment. (default: <date>")

	if len(os.Args) < 2 {
		log.Fatalln("Error: mstrusted: call with -V or -A.")
	}
	switch os.Args[1] {
	case "-V":
		verifyCommand.Parse(os.Args[2:])
		if file == "" {
			log.Fatalln("Error: mstrusted: set -m argument.")
		}
		if sigFile == "" {
			sigFile = file + ".minisig"
		}
		err := verify(file, sigFile)
		if err != nil {
			log.Fatalf("Error: %v\n", err)
		}
		if outputFlag {
			if err := outputFile(file); err != nil {
				log.Fatalf("Error: %v\n", err)
			}
		}
	case "-A":
		addCommand.Parse(os.Args[2:])
		if comment == "" {
			comment = "key added on " + time.Now().Format("2006-01-02")
		}
		err := add(pubKey, comment)
		if err != nil {
			log.Fatalf("Error: %v\n", err)
		}
	}
}

func add(pubKey string, comment string) error {
	return mstrusted.AddTrustedPubKey(pubKey, comment)
}

func verify(file string, sigFile string) error {
	key, comment, err := mstrusted.SearchTrustedPubKey(sigFile)
	if err != nil {
		return err
	}
	log.Printf("Verifying with %v (%v).\n", comment, mstrusted.EncodeID(key.KeyId))
	s, err := minisign.NewSignatureFromFile(sigFile)
	if err != nil {
		return err
	}
	_, err = key.VerifyFromFile(file, s)
	if err != nil {
		return err
	}
	log.Printf("Signature and comment signature verified.")
	return nil
}

func outputFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	const maxChunk = 4096
	b := make([]byte, maxChunk)
	for {
		readTotal, err := file.Read(b)
		if err != nil {
			if err != io.EOF {
				return err
			}
			break
		}
		fmt.Printf("%s", b[:readTotal])
	}
	return nil
}
