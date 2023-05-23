# Ed25519 private key derivation from master private key

Golang SLIP-0010 implementation(ed25519 only) according to the https://github.com/satoshilabs/slips/blob/master/slip-0010.md

## Example
```go
    package main

    import (
    	"encoding/hex"
    	"fmt"

    	slip10 "github.com/anyproto/go-slip10"
    )

    func main() {
    	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
    	if err != nil {
    		panic(err)
    	}

    	// example vector 1: https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-1-for-ed25519
    	node, err := slip10.DeriveForPath("m/0'/1'", seed)
    	if err != nil {
    		panic(err)
    	}

    	pub, priv, err := node.Keypair()
    	if err != nil {
    		panic(err)
    	}

    	// prints b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2
    	fmt.Printf("%x\n", priv)

    	// prints 1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187
    	// You can notice that example at https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-1-for-ed25519
    	// adds 0x00 prefix for the public key. Because we are using native crypto/ed25519 for the keypair we won't do this for the Keypair() method
    	fmt.Printf("%x\n", pub)

    	// but you can use node.PublicKeyWithPrefix() to get the public key with prefix
    	pubK, err := node.PublicKeyWithPrefix()
    	if err != nil {
    		panic(err)
    	}

    	// prints 001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187
    	fmt.Printf("%x\n", pubK)
    }
```

# Licensing

The code in this project is licensed under the MIT License
