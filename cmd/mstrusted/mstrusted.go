package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"aead.dev/minisign"
	"oskarsh.ru/mstrusted"
)

func main() {
	var (
		hashFlag        bool
		sigFile         string
		outputFlag      bool
		quietFlag       bool
		prettyQuietFlag bool
		file            string
	)
	flag.BoolVar(&hashFlag, "H", false, "require input to be prehashed.")
	flag.StringVar(&sigFile, "x", "", "signature file (default: <file>.minisig)")
	flag.BoolVar(&outputFlag, "o", false, "output the file content after verification")
	flag.BoolVar(&quietFlag, "q", false, "quiet mode, suppress output")
	flag.BoolVar(&prettyQuietFlag, "Q", false, "pretty quiet mode, only print the trusted comment")
	flag.StringVar(&file, "m", "", "file to verify.")
	flag.Parse()

	pubKey, err := mstrusted.SearchTrustedPubKey(sigFile)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	log.Println(pubKey)
	verifyFile(sigFile, "", pubKey, outputFlag, quietFlag, prettyQuietFlag, hashFlag, file)
}

// Code below was taken from https://github.com/aead/minisign/blob/0d530c6fc203bf1fee619d51809807cc3ed68e7d/cmd/minisign/minisign.go.
// Copyright (c) 2021 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the https://github.com/aead/minisign/blob/0d530c6fc203bf1fee619d51809807cc3ed68e7d/LICENSE file.

func verifyFile(sigFile, pubFile, pubKeyString string, printOutput, quiet, prettyQuiet, requireHash bool, files ...string) {
	if len(files) == 0 {
		log.Fatalf("Error: no files to verify. Use -m to specify a file path")
	}
	if len(files) > 1 {
		log.Fatalf("Error: too many files to verify. Only one file can be specified")
	}
	if sigFile == "" {
		sigFile = files[0] + ".minisig"
	}

	var (
		publicKey minisign.PublicKey
		err       error
	)
	if pubKeyString != "" {
		if err = publicKey.UnmarshalText([]byte(pubKeyString)); err != nil {
			log.Fatalf("Error: invalid public key: %v", err)
		}
	} else {
		publicKey, err = minisign.PublicKeyFromFile(pubFile)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
	}

	signature, err := minisign.SignatureFromFile(sigFile)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	if signature.KeyID != publicKey.ID() {
		log.Fatalf("Error: key IDs do not match. Try a different public key.\nID (public key): %X\nID (signature) : %X", publicKey.ID(), signature.KeyID)
	}

	rawSignature, _ := signature.MarshalText()
	if requireHash && signature.Algorithm != minisign.HashEdDSA {
		log.Fatal("Legacy (non-prehashed) signature found")
	}
	if signature.Algorithm == minisign.HashEdDSA || requireHash {
		file, err := os.Open(files[0])
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		reader := minisign.NewReader(file)
		if _, err = io.Copy(io.Discard, reader); err != nil {
			file.Close()
			log.Fatalf("Error: %v", err)
		}

		if !reader.Verify(publicKey, rawSignature) {
			file.Close()
			log.Fatal("Error: signature verification failed")
		}
		if !quiet {
			if !prettyQuiet {
				fmt.Println("Signature and comment signature verified")
			}
			fmt.Println("Trusted comment:", signature.TrustedComment)
		}
		if printOutput {
			if _, err = file.Seek(0, io.SeekStart); err != nil {
				file.Close()
				log.Fatalf("Error: %v", err)
			}
			if _, err = io.Copy(os.Stdout, bufio.NewReader(file)); err != nil {
				file.Close()
				log.Fatalf("Error: %v", err)
			}
		}
		file.Close()
	} else {
		message, err := os.ReadFile(files[0])
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		if !minisign.Verify(publicKey, message, rawSignature) {
			log.Fatal("Error: signature verification failed")
		}
		if !quiet {
			if !prettyQuiet {
				fmt.Println("Signature and comment signature verified")
			}
			fmt.Println("Trusted comment:", signature.TrustedComment)
		}
		if printOutput {
			os.Stdout.Write(message)
		}
	}
}
