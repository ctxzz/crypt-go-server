package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

func ReadPublicKey(path string) (*rsa.PublicKey, error) {
	publicKeyData, err := ioutil.ReadFile(path)
	checkError(err)
	publicKeyBlock, _ := pem.Decode([]byte(publicKeyData))
	if publicKeyBlock == nil {
		return nil, errors.New("bad public key data")
	}
	if publicKeyBlock.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unknown key type : %s", publicKeyBlock.Type)
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	checkError(err)

	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not RSA public key")
	}
	return publicKey, nil
}
