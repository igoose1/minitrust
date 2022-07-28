# Minitrust

Minitrust is a tool to verify minisign signatures with public keys from
"trusted list".

For more information about minisign, please refer to the [Minisign
documentation][minisign-docs]. As a core library and an only dependency
minitrust uses [go-minisign][go-minisign].

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

## Compile

Build from source with Go 1.17+.

	% go build -o . ./cmd/minitrust/minitrust.go

Also, building with redo is supported.

	% redo

For more information about redo, I recommend installing
[goredo](http://www.goredo.cypherpunks.ru/).
