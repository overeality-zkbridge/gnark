module github.com/consensys/gnark

go 1.17

require (
	github.com/consensys/bavard v0.1.13
	github.com/consensys/gnark-crypto v0.7.0
	github.com/fxamacker/cbor/v2 v2.2.0
	github.com/leanovate/gopter v0.2.9
	github.com/rs/zerolog v1.26.1
	github.com/stretchr/testify v1.8.0
)

replace github.com/fxamacker/cbor/v2 v2.2.0 => github.com/overeality-zkbridge/cbor/v2 v2.0.0-20220804005221-6dcd031a976c

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/pretty v0.3.0 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.0.0-20220722155217-630584e8d5aa // indirect
	golang.org/x/sys v0.0.0-20220727055044-e65921a090b8 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)
