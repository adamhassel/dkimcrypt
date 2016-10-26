package dkimcrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// Decrypt will decrypt the data in 'in' and return it in 'out', given the path to a PEM-encoded
// RSA private key file and a selector, which must be the same used for encryption
func Decrypt(selector, privkeypath string, in []byte) (out []byte, err error) {
	var pemData []byte
	var block *pem.Block
	var privkey *rsa.PrivateKey

	if pemData, err = ioutil.ReadFile(privkeypath); err != nil {
		return nil, fmt.Errorf("Error reading private key in '%s': %s", privkeypath, err)
	}

	block, _ = pem.Decode(pemData)

	if block == nil {
		return nil, fmt.Errorf("Bad key data in %s: Not PEM-encoded", privkeypath)
	}

	if got, want := block.Type, "RSA PRIVATE KEY"; got != want {
		return nil, fmt.Errorf("Unknown key type '%s', want '%s'", got, want)
	}

	if privkey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		return nil, fmt.Errorf("Bad private key: %s", err)
	}

	if out, err = rsa.DecryptOAEP(sha1.New(), rand.Reader, privkey, in, []byte(selector)); err != nil {
		return nil, fmt.Errorf("Decrypt: %s", err)
	}

	return out, nil

}

// Encrypt will encrypt the data given in 'in', and return the encrypted
// version in 'out', using the public key it finds in the DKIM-like TXT record
// at [selector]._domainkey.[domain]. Use the same selector in 'Decrypt'
func Encrypt(selector, domain string, in []byte) (out []byte, err error) {

	var pubkey *rsa.PublicKey
	if pubkey, err = getPubKey(selector, domain); err != nil {
		return nil, err
	}

	if out, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, pubkey, in, []byte(selector)); err != nil {
		return nil, err
	}

	return out, nil

}
