package dkimcrypt

import (
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
)

// SIgn will sign the message in 'message' using the private key in the file at 'privkeypath'.
func Sign(message []byte, privkeypath string) (out []byte, err error) {

	// Read the private key
	pemData, err := ioutil.ReadFile(privkeypath)
	if err != nil {
		return nil, fmt.Errorf("Error reading private key in '%s': %s", privkeypath, err)
	}

	// Extract the PEM-encoded data block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("bad key data: %s", "not PEM-encoded")
	}
	if got, want := block.Type, "RSA PRIVATE KEY"; got != want {
		return nil, fmt.Errorf("unknown key type %q, want %q", got, want)
	}

	// Decode the RSA private key
	privatekey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("bad private key: %s", err)
	}

	// SignPKCS1v15
	var h crypto.Hash
	hash := md5.New()
	io.WriteString(hash, string(message))
	hashed := hash.Sum(nil)
	h = crypto.MD5

	signature, err := rsa.SignPKCS1v15(rand.Reader, privatekey, h, hashed)

	if err != nil {
		return nil, err
	}

	return signature, nil

}

//func Verify(message []byte, signature []byte, publickey []byte) (bool, error) {

// Verify a signature given the signature, the message it signed and the
// selector and domain that signed it. If err is nil, then the signature is
// good.
func Verify(message []byte, signature []byte, selector, domain string) (err error) {

	var pubkey *rsa.PublicKey

	if pubkey, err = getPubKey(selector, domain); err != nil {
		return err
	}

	var h crypto.Hash
	hash := md5.New()
	io.WriteString(hash, string(message))
	hashed := hash.Sum(nil)
	h = crypto.MD5

	//VerifyPKCS1v15
	if err = rsa.VerifyPKCS1v15(pubkey, h, hashed, signature); err != nil {
		return err
	}

	return nil

}
