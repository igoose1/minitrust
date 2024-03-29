# Minitrust

Minitrust is a tool that verifies minisign signatures using public keys from a
trusted list. For more information about minisign, please see the [Minisign
documentation][minisign-docs]. Minitrust relies solely on
[go-minisign][go-minisign] as its core library and only dependency.

[minisign-docs]: https://jedisct1.github.io/minisign/
[go-minisign]: https://github.com/jedisct1/go-minisign/

## Usage

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

## Install

The easiest way to install it is with `go install`:

    % go install github.com/igoose1/minitrust@latest

## Compile

If you have a source code, you can build it with Go 1.21+.

    % go build
