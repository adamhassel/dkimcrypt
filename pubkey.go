// This is sourced from https://github.com/toorop/go-dkim/blob/master/pubKeyRep.go

// Package dkimcrypt provides convenient functions for en- or decrypting, as
// well as signing and verifying data using a combination of local private key
// files and public keys present in DKIM DNS TXT records
package dkimcrypt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
)

// pubKeyRep represents a parsed version of public key record
type pubKeyRep struct {
	Version      string
	HashAlgo     []string
	KeyType      string
	Note         string
	PubKey       rsa.PublicKey
	ServiceType  []string
	FlagTesting  bool // flag y
	FlagIMustBeD bool // flag i
}

func newPubKeyFromDnsTxt(selector, domain string) (*pubKeyRep, error) {
	txt, err := net.LookupTXT(selector + "._domainkey." + domain)
	if err != nil {
		if strings.HasSuffix(err.Error(), "no such host") {
			return nil, fmt.Errorf("No key found for %s", domain)
		} else {
			return nil, fmt.Errorf("Service not available")
		}
	}

	// empty record
	if len(txt) == 0 {
		return nil, fmt.Errorf("No key found for %s", domain)
	}

	pkr := new(pubKeyRep)
	pkr.Version = "DKIM1"
	pkr.HashAlgo = []string{"sha1", "sha256"}
	pkr.KeyType = "rsa"
	pkr.ServiceType = []string{"all"}
	pkr.FlagTesting = false
	pkr.FlagIMustBeD = false

	// parsing, we keep the first record
	// TODO: if there is multiple record

	p := strings.Split(txt[0], ";")
	for i, data := range p {
		keyVal := strings.SplitN(data, "=", 2)
		val := ""
		if len(keyVal) > 1 {
			val = strings.TrimSpace(keyVal[1])
		}
		switch strings.ToLower(strings.TrimSpace(keyVal[0])) {
		case "v":
			// RFC: is this tag is specified it MUST be the first in the record
			if i != 0 {
				return nil, fmt.Errorf("Record syntax error: V tag must be first")
			}
			pkr.Version = val
			if pkr.Version != "DKIM1" {
				return nil, fmt.Errorf("Version was not DKIM 1")
			}
		case "h":
			p := strings.Split(strings.ToLower(val), ":")
			pkr.HashAlgo = []string{}
			for _, h := range p {
				h = strings.TrimSpace(h)
				if h == "sha1" || h == "sha256" {
					pkr.HashAlgo = append(pkr.HashAlgo, h)
				}
			}
			// if empty switch back to default
			if len(pkr.HashAlgo) == 0 {
				pkr.HashAlgo = []string{"sha1", "sha256"}
			}
		case "k":
			if strings.ToLower(val) != "rsa" {
				return nil, fmt.Errorf("Bad key type, must be 'rsa'")
			}
		case "n":
			pkr.Note = val
		case "p":
			rawkey := val
			if rawkey == "" {
				return nil, fmt.Errorf("Key revoked")
			}
			un64, err := base64.StdEncoding.DecodeString(rawkey)
			if err != nil {
				return nil, fmt.Errorf("Public key parse error")
			}
			pk, err := x509.ParsePKIXPublicKey(un64)
			pkr.PubKey = *pk.(*rsa.PublicKey)
		case "s":
			t := strings.Split(strings.ToLower(val), ":")
			for _, tt := range t {
				if tt == "*" {
					pkr.ServiceType = []string{"all"}
					break
				}
				if tt == "email" {
					pkr.ServiceType = []string{"email"}
				}
			}
		case "t":
			flags := strings.Split(strings.ToLower(val), ":")
			for _, flag := range flags {
				if flag == "y" {
					pkr.FlagTesting = true
					continue
				}
				if flag == "s" {
					pkr.FlagIMustBeD = true
				}
			}
		}
	}

	// if no pubkey
	if pkr.PubKey == (rsa.PublicKey{}) {
		return nil, fmt.Errorf("No public key found")
	}

	return pkr, nil
}

func getPubKey(selector, domain string) (*rsa.PublicKey, error) {
	rep, err := newPubKeyFromDnsTxt(selector, domain)

	if err != nil {
		return nil, err
	}

	return &rep.PubKey, nil
}
