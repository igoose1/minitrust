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

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/igoose1/minitrust/pkg/minitrust"
	"github.com/jedisct1/go-minisign"
)

const Usage = `Usage:
minitrust -V [-x sigfile] [-o] -m file
minitrust -T [-c comment] -P pubkey

-V             verify that a signature is valid for a given file
-T             add new public key to list of "trusted"
-x             signature file (default: <file>.minisig)
-o             output the file content after verification
-m             file to verify
-P             public key, as a base64 string
-c             one-line untrusted comment

Environment variables:

MINITRUST_DIR  name of the trusted directory (default: ~/.minisign/trusted)
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
		trustedDir string
	)
	verifyCommand := flag.NewFlagSet("-V", flag.ExitOnError)
	verifyCommand.StringVar(&sigFile, "x", "", "signature file (default: <file>.minisig)")
	verifyCommand.BoolVar(&outputFlag, "o", false, "output the file content after verification")
	verifyCommand.StringVar(&file, "m", "", "file to verify.")
	verifyCommand.Usage = func() { fmt.Fprint(os.Stderr, Usage) }

	addCommand := flag.NewFlagSet("-T", flag.ExitOnError)
	addCommand.StringVar(&pubKey, "P", "", "public key, as a base64 string")
	addCommand.StringVar(&comment, "c", "", "one-line untrusted comment")
	addCommand.Usage = func() { fmt.Fprint(os.Stderr, Usage) }

	trustedDir = os.Getenv("MINITRUST_DIR")
	if trustedDir == "" {
		homedir, err := os.UserHomeDir()
		if err != nil {
			logger.Fatal(err)
		}
		trustedDir = filepath.Join(homedir, ".minisign", "trusted")
	}

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
		err := verify(trustedDir, file, sigFile)
		if err != nil {
			logger.Fatalf("Error: %v\n", err)
		}
		if outputFlag {
			if err := outputFile(file); err != nil {
				logger.Fatalf("Error: %v\n", err)
			}
		}
	case "-T":
		addCommand.Parse(os.Args[2:])
		if comment == "" {
			comment = "key added on " + time.Now().Format("2006-01-02")
		}
		err := add(trustedDir, pubKey, comment)
		if err != nil {
			logger.Fatalf("Error: %v\n", err)
		}
	default:
		fmt.Fprint(os.Stderr, Usage)
	}
}

func add(trustedDir, pubKey, comment string) error {
	b := minitrust.New(trustedDir)
	return b.AddTrustedPubKey(pubKey, comment)
}

func verify(trustedDir, file, sigFile string) error {
	b := minitrust.New(trustedDir)
	key, comment, err := b.SearchTrustedPubKey(sigFile)
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

func outputFile(readFrom string) error {
	file, err := os.Open(readFrom)
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
