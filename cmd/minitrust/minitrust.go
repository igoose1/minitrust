package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/igoose1/minitrust"
	"github.com/jedisct1/go-minisign"
)

const Usage = `Usage:
minitrust -V [-x sigfile] [-o] -m file
minitrust -A [-c comment] -P pubkey

-V		verify that a signature is valid for a given file
-A		add new public key to trusted directory
-x		signature file (default: <file>.minisig)
-o		output the file content after verification
-m		file to verify
-P		public key, as a base64 string
-c		one-line untrusted comment
`

var logger = log.New(os.Stderr, "", log.Lshortfile)

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
	verifyCommand.Usage = func() { fmt.Fprint(os.Stderr, Usage) }

	addCommand := flag.NewFlagSet("-A", flag.ExitOnError)
	addCommand.StringVar(&pubKey, "P", "", "public key, as a base64 string")
	addCommand.StringVar(&comment, "c", "", "one-line untrusted comment")
	addCommand.Usage = func() { fmt.Fprint(os.Stderr, Usage) }

	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, Usage)
		os.Exit(0)
	}
	switch os.Args[1] {
	case "-V":
		verifyCommand.Parse(os.Args[2:])
		if file == "" {
			logger.Fatalln("Error: minitrust: set -m argument.")
		}
		if sigFile == "" {
			sigFile = file + ".minisig"
		}
		err := verify(file, sigFile)
		if err != nil {
			logger.Fatalf("Error: %v\n", err)
		}
		if outputFlag {
			if err := outputFile(file); err != nil {
				logger.Fatalf("Error: %v\n", err)
			}
		}
	case "-A":
		addCommand.Parse(os.Args[2:])
		if comment == "" {
			comment = "key added on " + time.Now().Format("2006-01-02")
		}
		err := add(pubKey, comment)
		if err != nil {
			logger.Fatalf("Error: %v\n", err)
		}
	default:
		fmt.Fprint(os.Stderr, Usage)
	}
}

func add(pubKey string, comment string) error {
	return minitrust.AddTrustedPubKey(pubKey, comment)
}

func verify(file string, sigFile string) error {
	key, comment, err := minitrust.SearchTrustedPubKey(sigFile)
	if err != nil {
		return err
	}
	logger.Printf("Verifying with %v (%v).\n", comment, minitrust.EncodeID(key.KeyId))
	s, err := minisign.NewSignatureFromFile(sigFile)
	if err != nil {
		return err
	}
	_, err = key.VerifyFromFile(file, s)
	if err != nil {
		return err
	}
	logger.Printf("Signature and comment signature verified.")
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
