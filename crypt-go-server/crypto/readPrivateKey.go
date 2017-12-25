package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

func ReadPrivateKey(path string) (*rsa.PrivateKey, error) {
	privateKeyData, err := ioutil.ReadFile(path)
	checkError(err)
	privateKeyBlock, _ := pem.Decode([]byte(privateKeyData))
	if privateKeyBlock == nil {
		return nil, errors.New("bad private key data")
	}
	if privateKeyBlock.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("unknown key type : %s", privateKeyBlock.Type)
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	checkError(err)
	return privateKey, nil
}
