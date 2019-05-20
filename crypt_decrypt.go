package dkimcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

// KeySize and MacSize are the sizes in bits of the AES key and the Authentication Code, respectively
const (
	keySize = sha256.Size * 8
	macSize = sha256.Size
)

func rsaDecrypt(selector, privkeypath string, in []byte) (out []byte, err error) {
	var privkey *rsa.PrivateKey

	if privkey, err = getPrivKeyFromFile(privkeypath); err != nil {
		return nil, fmt.Errorf("couldn't read private key: %s", err)
	}

	if out, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, privkey, in, []byte(selector)); err != nil {
		return nil, fmt.Errorf("decrypt: %s", err)
	}

	return out, nil
}

func rsaEncrypt(selector, domain string, in []byte) (out []byte, err error) {
	var pubkey *rsa.PublicKey
	if pubkey, err = getPubKey(selector, domain); err != nil {
		return nil, err
	}

	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pubkey, in, []byte(selector))
}

func aesDecrypt(key, ciphertext []byte) (plaintext []byte, err error) {
	var block cipher.Block

	if block, err = aes.NewCipher(key); err != nil {
		return
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
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
	if len(in) < keySize+macSize {
		return nil, fmt.Errorf("Data length too short")
	}

	crypt, key, mac := deconstructcryptdata(in)

	return Decrypt(selector, privkeypath, crypt, key, mac)
}

// EncryptSingle is a wrapper around Encrypt, which will encrypt a byte slice
// and return a single byte slice representing a key, a verification hash and
// the ecrypted data, useful for sending over a network. Decrypt using
// DecryptSingle
func EncryptSingle(selector, domain string, in []byte) (out []byte, err error) {
	var crypt, key, mac []byte

	if crypt, key, mac, err = Encrypt(selector, domain, in); err == nil {
		return constructcryptdata(crypt, key, mac), err
	}
	return nil, err
}

// Decrypt will decrypt the data in 'in' and return it in 'out', given the path
// to a PEM-encoded private key file, an RSA-encrypted key, a message
// authentication code hash, and a selector, which must be the same used for
// encryption
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
		return nil, errors.New("encrypted data could not be authenticated")
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
	key = make([]byte, keySize/8)

	if _, err = rand.Read(key); err != nil {
		return nil, err
	}

	return key, nil
}

func constructcryptdata(crypt, key, mac []byte) (cryptdata []byte) {
	cryptdata = make([]byte, 0, len(mac)+len(key)+len(crypt))

	cryptdata = append(cryptdata, mac...)
	cryptdata = append(cryptdata, key...)
	cryptdata = append(cryptdata, crypt...)

	return
}

func deconstructcryptdata(cryptdata []byte) (data, key, mac []byte) {

	data = make([]byte, len(cryptdata)-keySize-macSize)
	key = make([]byte, keySize)
	mac = make([]byte, macSize)

	mac, key, data = cryptdata[:macSize], cryptdata[macSize:macSize+keySize], cryptdata[macSize+keySize:]

	return
}
