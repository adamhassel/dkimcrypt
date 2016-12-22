package dkimcrypt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func getPrivKeyFromFile(filename string) (key *rsa.PrivateKey, err error) {
	var pemData []byte
	var block *pem.Block
	var privkey *rsa.PrivateKey

	if pemData, err = ioutil.ReadFile(filename); err != nil {
		return nil, fmt.Errorf("Error reading private key in '%s': %s", filename, err)
	}

	block, _ = pem.Decode(pemData)

	if block == nil {
		return nil, fmt.Errorf("Bad key data in %s: Not PEM-encoded", filename)
	}

	switch block.Type {
	case "PRIVATE KEY":
		var tmp interface{}
		if tmp, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, fmt.Errorf("Bad private key: %s", err)
		}
		privkey = tmp.(*rsa.PrivateKey)
	case "RSA PRIVATE KEY":
		if privkey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			return nil, fmt.Errorf("Bad private key: %s", err)
		}
	default:
		return nil, fmt.Errorf("Unknown key type '%s', want either '%s' or '%s'", block.Type, "PRIVATE KEY", "RSA PRIVATE KEY")
	}

	return privkey, nil
}
