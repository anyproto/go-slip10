package slip10

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	// FirstHardenedIndex is the index of the first hardened key (2^31).
	// https://youtu.be/2HrMlVr1QX8?t=390
	FirstHardenedIndex = uint32(0x80000000)
	// As in https://github.com/satoshilabs/slips/blob/master/slip-0010.md
	seedModifier = "ed25519 seed"
)

var (
	ErrInvalidPath        = fmt.Errorf("invalid derivation path")
	ErrNoPublicDerivation = fmt.Errorf("no public derivation for ed25519")

	pathRegex = regexp.MustCompile("^m(/[0-9]+')*$")
)

type Node struct {
	chainCode []byte
	key       []byte
}

// DeriveForPath derives key for a path in BIP-44 format and a seed.
// Ed25119 derivation operated on hardened keys only.
func DeriveForPath(path string, seed []byte) (*Node, error) {
	if !IsValidPath(path) {
		return nil, ErrInvalidPath
	}

	key, err := NewMasterNode(seed)
	if err != nil {
		return nil, err
	}

	segments := strings.Split(path, "/")
	for _, segment := range segments[1:] {
		i64, err := strconv.ParseUint(strings.TrimRight(segment, "'"), 10, 32)
		if err != nil {
			return nil, err
		}

		// we operate on hardened keys
		i := uint32(i64) + FirstHardenedIndex
		key, err = key.Derive(i)
		if err != nil {
			return nil, err
		}
	}

	return key, nil
}

// NewMasterNode generates a new master key from seed.
func NewMasterNode(seed []byte) (*Node, error) {
	hash := hmac.New(sha512.New, []byte(seedModifier))
	_, err := hash.Write(seed)
	if err != nil {
		return nil, err
	}
	sum := hash.Sum(nil)
	key := &Node{}
	toNode(key, sum)
	return key, nil
}

func (k *Node) Derive(i uint32) (*Node, error) {
	// no public derivation for ed25519
	if i < FirstHardenedIndex {
		return nil, ErrNoPublicDerivation
	}

	iBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(iBytes, i)
	key := append([]byte{0x0}, k.key...)
	data := append(key, iBytes...)

	hash := hmac.New(sha512.New, k.chainCode)
	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}
	sum := hash.Sum(nil)
	newKey := &Node{}
	toNode(newKey, sum)
	return newKey, nil
}

// Keypair returns the public and private key.
func (k *Node) Keypair() (ed25519.PublicKey, ed25519.PrivateKey) {
	reader := bytes.NewReader(k.key)
	pub, priv, err := ed25519.GenerateKey(reader)
	if err != nil {
		// can't happens because we check the seed on NewMasterNode/DeriveForPath
		return nil, nil
	}

	return pub[:], priv[:]
}

// RawSeed returns raw seed bytes
func (k *Node) RawSeed() []byte {
	return k.key
}

// PrivateKey returns private key seed bytes
func (k *Node) PrivateKey() []byte {
	_, priv := k.Keypair()
	return priv.Seed()
}

// PublicKeyWithPrefix returns public key with 0x00 prefix, as specified in the slip-10
// https://github.com/satoshilabs/slips/blob/master/slip-0010/testvectors.py#L64
func (k *Node) PublicKeyWithPrefix() []byte {
	pub, _ := k.Keypair()
	return append([]byte{0x00}, pub...)
}

// IsValidPath check whether or not the path has valid segments.
func IsValidPath(path string) bool {
	if !pathRegex.MatchString(path) {
		return false
	}

	// check for overflows
	segments := strings.Split(path, "/")
	for _, segment := range segments[1:] {
		_, err := strconv.ParseUint(strings.TrimRight(segment, "'"), 10, 32)
		if err != nil {
			return false
		}
	}

	return true
}

func toNode(node *Node, sum []byte) {
	node.key = sum[:32]
	node.chainCode = sum[32:]
}
