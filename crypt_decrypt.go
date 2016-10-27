package dkimcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
)

func rsaDecrypt(selector, privkeypath string, in []byte) (out []byte, err error) {
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

func rsaEncrypt(selector, domain string, in []byte) (out []byte, err error) {

	var pubkey *rsa.PublicKey
	if pubkey, err = getPubKey(selector, domain); err != nil {
		return nil, err
	}

	if out, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, pubkey, in, []byte(selector)); err != nil {
		return nil, err
	}

	return out, nil

}

func aesDecrypt(key, ciphertext []byte) (plaintext []byte, err error) {

	var block cipher.Block

	if block, err = aes.NewCipher(key); err != nil {
		return
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(ciphertext, ciphertext)

	plaintext = ciphertext

	return
}

func aesEncrypt(key, text []byte) (ciphertext []byte, err error) {

	var block cipher.Block

	if block, err = aes.NewCipher(key); err != nil {
		return nil, err
	}

	ciphertext = make([]byte, aes.BlockSize+len(string(text)))

	// iv =  initialization vector
	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], text)

	return
}

// Decrypt will decrypt the data in 'in' and return it in 'out', given the path to a PEM-encoded
// RSA private key file, an RSA-encrypted key and a selector, which must be the same used for encryption
func Decrypt(selector, privkeypath string, in, key []byte) (out []byte, err error) {

	var uk []byte // unencrypted key

	if uk, err = rsaDecrypt(selector, privkeypath, key); err != nil {
		return nil, err
	}

	if out, err = aesDecrypt(uk, in); err != nil {
		return nil, err
	}

	return out, nil

}

// Encrypt will AES-encrypt the data given in 'in', and return the encrypted
// version in 'out', as well as a key, which is RSA-encrypted using the public
// key it finds in the DKIM-like TXT record at [selector]._domainkey.[domain].
// Use the same selector in 'Decrypt'
func Encrypt(selector, domain string, in []byte) (out, key []byte, err error) {

	var uk []byte // unencrypted, random 32-byte key
	if uk, err = makekey(); err != nil {
		return nil, nil, err
	}

	if key, err = rsaEncrypt(selector, domain, uk); err != nil {
		return nil, nil, err
	}

	if out, err = aesEncrypt(uk, in); err != nil {
		return nil, nil, err
	}

	return out, key, nil

}

// Make a 32 bit random key
func makekey() (key []byte, err error) {
	key = make([]byte, 32)

	if _, err = rand.Read(key); err != nil {
		return nil, err
	}

	return key, nil
}
