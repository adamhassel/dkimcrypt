package dkimcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
)

// KeySize and MacSize are the sizes in bits of the AES key and the Authentication Code, respectively
const (
	KeySize = sha256.Size * 8
	MacSize = sha256.Size
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

	if out, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, privkey, in, []byte(selector)); err != nil {
		return nil, fmt.Errorf("Decrypt: %s", err)
	}

	return out, nil

}

func rsaEncrypt(selector, domain string, in []byte) (out []byte, err error) {

	var pubkey *rsa.PublicKey
	if pubkey, err = getPubKey(selector, domain); err != nil {
		return nil, err
	}

	if out, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pubkey, in, []byte(selector)); err != nil {
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

// DecryptSingle is a wrapper around Decrypt, which will decrypt a byte slice
// encrypted by EncryptSingle
func DecryptSingle(selector, privkeypath string, in []byte) (out []byte, err error) {

	crypt, key, mac := deconstructcryptdata(in)

	return Decrypt(selector, privkeypath, crypt, key, mac)
}

// EncryptSingle is a wrapper around Encrypt, which will encrypt a byte slice
// and return a single byte slice representing a key, a verification hash and
// the ecrypted data, useful for sendingover a network. Decrypt using
// DecryptSingle
func EncryptSingle(selector, domain string, in []byte) (out []byte, err error) {

	if crypt, key, mac, err := Encrypt(selector, domain, in); err == nil {
		return constructcryptdata(crypt, key, mac), err
	}
	return nil, err

}

// Decrypt will decrypt the data in 'in' and return it in 'out', given the path to a PEM-encoded
// RSA private key file, an RSA-encrypted key, a message authentication code hash,
// and a selector, which must be the same used for encryption
func Decrypt(selector, privkeypath string, in, key, mac []byte) (out []byte, err error) {

	var uk []byte // unencrypted key

	if uk, err = rsaDecrypt(selector, privkeypath, key); err != nil {
		return nil, err
	}

	if out, err = aesDecrypt(uk, in); err != nil {
		return nil, err
	}

	// Verify
	hash := hmac.New(sha256.New, uk)
	hash.Write(out)
	checkmac := hash.Sum(nil)

	if !hmac.Equal(mac, checkmac) {
		return nil, fmt.Errorf("Encrypted data could not be authenticated")
	}

	return out, nil

}

// Encrypt will AES-encrypt the data given in 'in', and return the encrypted
// version in 'out', as well as a key, which is RSA-encrypted using the public
// key it finds in the DKIM-like TXT record at [selector]._domainkey.[domain],
// and a message authentication code hash.  Use the same selector in 'Decrypt'
func Encrypt(selector, domain string, in []byte) (out, key, mac []byte, err error) {

	var uk []byte // unencrypted, random 32-byte key
	if uk, err = makekey(); err != nil {
		return nil, nil, nil, err
	}

	if key, err = rsaEncrypt(selector, domain, uk); err != nil {
		return nil, nil, nil, err
	}

	if out, err = aesEncrypt(uk, in); err != nil {
		return nil, nil, nil, err
	}

	// Sign
	hash := hmac.New(sha256.New, uk)
	hash.Write(in)
	mac = hash.Sum(nil)

	return out, key, mac, nil

}

// Make a 32 byte random key
func makekey() (key []byte, err error) {
	key = make([]byte, KeySize/8)

	if _, err = rand.Read(key); err != nil {
		return nil, err
	}

	return key, nil
}

func constructcryptdata(crypt, key, mac []byte) (cryptdata []byte) {

	cryptdata = make([]byte, 0)

	cryptdata = append(cryptdata, mac...)
	cryptdata = append(cryptdata, key...)
	cryptdata = append(cryptdata, crypt...)

	return
}

func deconstructcryptdata(cryptdata []byte) (data, key, mac []byte) {

	data = make([]byte, len(cryptdata)-KeySize-MacSize)
	key = make([]byte, KeySize)
	mac = make([]byte, MacSize)

	mac, key, data = cryptdata[:MacSize], cryptdata[MacSize:MacSize+KeySize], cryptdata[MacSize+KeySize:]

	return
}
