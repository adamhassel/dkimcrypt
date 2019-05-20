package dkimcrypt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

const PRIVKEY = "PRIVATE KEY"
const RSAKEY = "RSA PRIVATE KEY"

func getPrivKeyFromFile(filename string) (key *rsa.PrivateKey, err error) {
	var pemData []byte
	var block *pem.Block
	var privkey *rsa.PrivateKey

	if pemData, err = ioutil.ReadFile(filename); err != nil {
		return nil, fmt.Errorf("error reading private key in '%s': %s", filename, err)
	}

	block, _ = pem.Decode(pemData)

	if block == nil {
		return nil, fmt.Errorf("bad key data in %s: Not PEM-encoded", filename)
	}

	switch block.Type {
	case PRIVKEY:
		var tmp interface{}
		if tmp, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, fmt.Errorf("bad private key: %s", err)
		}
		privkey = tmp.(*rsa.PrivateKey)
	case RSAKEY:
		if privkey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			return nil, fmt.Errorf("bad private key: %s", err)
		}
	default:
		return nil, fmt.Errorf("unknown key type '%s', want either '%s' or '%s'", block.Type, PRIVKEY, RSAKEY)
	}

	return privkey, nil
}

// GetPrivateKey loads a private key from the given filename and returns it.
func GetPrivateKey(filename string) (*rsa.PrivateKey, error) {
	return getPrivKeyFromFile(filename)
}
