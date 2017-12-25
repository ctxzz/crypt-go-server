package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

func GenerateRSAKey() {
	size := 2048
	//Generate Private Key
	privateKey, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		log.Fatal(err)
	}

	privateKeyDer := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyDer,
	}
	privateKeyPem := string(pem.EncodeToMemory(&privateKeyBlock))
	fmt.Println(privateKeyPem)

	publicKey := privateKey.PublicKey
	publicKeyDer, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		log.Fatal(err)
	}
	publicKeyBlock := pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   publicKeyDer,
	}
	publicKeyPem := string(pem.EncodeToMemory(&publicKeyBlock))
	fmt.Println(publicKeyPem)

	privateKeyOut, err := os.OpenFile("privateKey.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Print("failed to open privateKey.pem for writing:", err)
		return
	}
	pem.Encode(privateKeyOut, &privateKeyBlock)
	privateKeyOut.Close()
	log.Print("written private.pem\n")

	publicKeyOut, err := os.OpenFile("publicKey.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Print("failed to open publicKey.pem for writing:", err)
		return
	}
	pem.Encode(publicKeyOut, &publicKeyBlock)
	publicKeyOut.Close()
	log.Print("written public.pem\n")
}
