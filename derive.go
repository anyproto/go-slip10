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
	DefaultSeedModifier = "ed25519 seed"
)

var (
	ErrInvalidPath        = fmt.Errorf("invalid derivation path")
	ErrNoPublicDerivation = fmt.Errorf("no public derivation for ed25519")

	pathRegex = regexp.MustCompile("^m(/[0-9]+')*$")
)

type Node interface {
	Derive(i uint32) (Node, error)

	Keypair() (ed25519.PublicKey, ed25519.PrivateKey)
	PrivateKey() []byte
	PublicKeyWithPrefix() []byte
	RawSeed() []byte
	MarshalBinary() ([]byte, error)
}

type node struct {
	chainCode []byte
	key       []byte
}

// DeriveForPath derives the node at `path` starting from a ROOT seed.
//
// Use this when you have the rootSeed(e.g. extracted from the mnemonic) and a derivation path, and you
// want to deterministically re-create the SAME node every time from the root.
//
// Do NOT pass a node's RawSeed() here — that 32-byte value is only the ed25519
// key seed for that node and does not include its chain code. Feeding it here
// creates a NEW unrelated root.
func DeriveForPath(path string, rootSeed []byte) (Node, error) {
	if !IsValidPath(path) {
		return nil, ErrInvalidPath
	}

	key, err := NewMasterNode(rootSeed)
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

// NewMasterNode constructs the SLIP-0010 *master node* from a ROOT seed.
//
// Use this when you have the original root entropy and want to (re)build a tree
// deterministically from the top (e.g., together with a path like "m/44'/...").
// Uses DefaultSeedModifier as the seed modifier.
// Security: anyone with rootSeed can derive the entire tree. Treat as highly sensitive.
//
// rootSeed: arbitrary-length seed per SLIP-0010 (typically 16–64 bytes).
func NewMasterNode(rootSeed []byte) (Node, error) {
	return NewMasterNodeWithModifier(DefaultSeedModifier, rootSeed)
}

// NewMasterNodeWithModifier is like NewMasterNode but with a custom seed modifier.
//
// This is for special cases not covered by the default function, such as deriving Curve25519 secrets.
//
// seedModifier: custom string used as a key for HMAC as per SLIP-0010.
// rootSeed: arbitrary-length seed per SLIP-0010 (typically 16–64 bytes).
func NewMasterNodeWithModifier(seedModifier string, rootSeed []byte) (Node, error) {
	hash := hmac.New(sha512.New, []byte(seedModifier))
	_, err := hash.Write(rootSeed)
	if err != nil {
		return nil, err
	}
	sum := hash.Sum(nil)
	key := &node{
		key:       sum[:32],
		chainCode: sum[32:],
	}
	return key, nil
}

func (k *node) Derive(i uint32) (Node, error) {
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
	newKey := &node{
		key:       sum[:32],
		chainCode: sum[32:],
	}
	return newKey, nil
}

// PrivateKey returns private key for a derived private key.
func (k *node) Keypair() (ed25519.PublicKey, ed25519.PrivateKey) {
	reader := bytes.NewReader(k.key)
	pub, priv, err := ed25519.GenerateKey(reader)
	if err != nil {
		// can't happens because we check the seed on NewMasterNode/DeriveForPath
		return nil, nil
	}

	return pub[:], priv[:]
}

// RawSeed returns this node’s 32-byte Ed25519 private key seed (the value you
// would pass to ed25519.NewKeyFromSeed). It is *not* the SLIP-0010 master seed
// and it does *not* include the 32-byte chain code.
//
// Use when:
//   - You need the Ed25519 signing key for this node:
//     priv := ed25519.NewKeyFromSeed(n.RawSeed())
//   - You must export/import a 32-byte Ed25519 seed for compatibility with
//     other libraries or formats.
//
// Do NOT use when:
//   - Rehydrating a node for further derivation — RawSeed() alone is insufficient.
//     To restore a node and derive children, you also need its chain code;
//     use MarshalBinary/UnmarshalNode instead.
//   - Creating a new master/root: passing RawSeed() into NewMasterNode/DeriveForPath
//     produces a *new, unrelated* root and changes the blast radius.
//
// Security: RawSeed() recovers the node’s signing key
func (k *node) RawSeed() []byte {
	return k.key
}

// PrivateKey returns private key seed bytes
func (k *node) PrivateKey() []byte {
	_, priv := k.Keypair()
	return priv.Seed()
}

// PublicKeyWithPrefix returns public key with 0x00 prefix, as specified in the slip-10
// https://github.com/satoshilabs/slips/blob/master/slip-0010/testvectors.py#L64
func (k *node) PublicKeyWithPrefix() []byte {
	pub, _ := k.Keypair()
	return append([]byte{0x00}, pub...)
}

// MarshalBinary serializes the node's extended private key as key||chainCode (64 bytes).
// Use this to persist a checkpoint so you can restore the node later without the root seed.
// Security: anyone with this blob can derive all descendants of this node.
func (k *node) MarshalBinary() ([]byte, error) {
	// [32]key || [32]chainCode
	b := make([]byte, 64)
	copy(b[:32], k.key)
	copy(b[32:], k.chainCode)
	return b, nil
}

// UnmarshalNode restores a node from a 64-byte key||chainCode blob produced by MarshalBinary.
// Use this when you saved a node checkpoint and want to continue deriving BELOW that node.
func UnmarshalNode(b []byte) (Node, error) {
	if len(b) != 64 {
		return nil, fmt.Errorf("invalid node blob length: %d", len(b))
	}
	n := &node{
		key:       append([]byte(nil), b[:32]...),
		chainCode: append([]byte(nil), b[32:]...),
	}
	return n, nil
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
