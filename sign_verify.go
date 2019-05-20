package dkimcrypt

import (
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"io"
)

// Sign will return the signature of the message in 'message' using the private
// key in the file at 'privkeypath'.
func Sign(message []byte, privkeypath string) (out []byte, err error) {
	var privatekey *rsa.PrivateKey

	if privatekey, err = getPrivKeyFromFile(privkeypath); err != nil {
		return nil, err
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

// Verify a signature given the signature, the message it signed and the
// selector and domain that signed it. If err is nil, then the signature is
// good.
func Verify(message, signature []byte, selector, domain string) (err error) {
	var pubkey *rsa.PublicKey

	if pubkey, err = getPubKey(selector, domain); err != nil {
		return err
	}

	var h crypto.Hash
	hash := md5.New()
	io.WriteString(hash, string(message))
	hashed := hash.Sum(nil)
	h = crypto.MD5

	return rsa.VerifyPKCS1v15(pubkey, h, hashed, signature)
}
