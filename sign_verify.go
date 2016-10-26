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

func Sign(message []byte, privkeypath string) ([]byte, error) {

	// Read the private key
	pemData, err := ioutil.ReadFile(privkeypath)
	if err != nil {
		return nil, err
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

// Verify a signature given the signature, the message it signed and a correct public key.
func Verify(message []byte, signature []byte, publickey []byte) (bool, error) {

	// Decode RSA Public key
	// Extract the PEM-encoded data block
	block, _ := pem.Decode(publickey)
	if block == nil {
		return false, fmt.Errorf("bad key data: %s", "not PEM-encoded")
	}
	if got, want := block.Type, "PUBLIC KEY"; got != want {
		return false, fmt.Errorf("unknown key type %q, want %q", got, want)
	}
	publickeyif, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("bad public key: %s", err)
	}
	pubkey, ok := publickeyif.(*rsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("Parsing type error")
	}

	var h crypto.Hash
	hash := md5.New()
	io.WriteString(hash, string(message))
	hashed := hash.Sum(nil)
	h = crypto.MD5

	//VerifyPKCS1v15
	err = rsa.VerifyPKCS1v15(pubkey, h, hashed, signature)

	if err != nil {
		return true, nil
	} else {
		return false, nil
	}

}
