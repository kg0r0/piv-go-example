package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"

	"github.com/go-piv/piv-go/piv"
)

func main() {
	cards, err := piv.Cards()
	if err != nil {
		// ...
	}

	var yk *piv.YubiKey
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			if yk, err = piv.Open(card); err != nil {
				// ...
			}
			break
		}
	}
	if yk == nil {
		// ...
	}

	if err := yk.Reset(); err != nil {
		fmt.Errorf("reset yubikey: %v", err)
	}

	slot := piv.SlotSignature

	key := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		TouchPolicy: piv.TouchPolicyAlways,
		PINPolicy:   piv.PINPolicyAlways,
	}
	pubKey, err := yk.GenerateKey(piv.DefaultManagementKey, slot, key)
	if err != nil {
		fmt.Errorf("generating key: %v", err)
	}
	pub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		fmt.Errorf("public key is not an ecdsa key")
	}
	auth := piv.KeyAuth{PIN: piv.DefaultPIN}
	data := sha256.Sum256([]byte("hello"))
	priv, err := yk.PrivateKey(slot, pub, auth)
	if err != nil {
		fmt.Errorf("getting private key: %v", err)
	}
	s, ok := priv.(crypto.Signer)
	if !ok {
		fmt.Errorf("expected private key to implement crypto.Signer")
	}
	out, err := s.Sign(rand.Reader, data[:], crypto.SHA256)
	if err != nil {
		fmt.Errorf("signing failed: %v", err)
	}
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(out, &sig); err != nil {
		fmt.Errorf("unmarshaling signature: %v", err)
	}
	if !ecdsa.Verify(pub, data[:], sig.R, sig.S) {
		fmt.Errorf("signature didn't match")
	}
}
