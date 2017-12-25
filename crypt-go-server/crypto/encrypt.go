package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"io"
	"log"
)

func RsaEncrypt(in []byte, pub *rsa.PublicKey) ([]byte, error) {
	sha1 := sha1.New()
	out, err := rsa.EncryptOAEP(sha1, rand.Reader, pub, in, nil)
	if err != nil {
		log.Fatalf("Failed to encrypt message %v", err)
		return nil, err
	}
	return out, nil
}

func AesEncrypt(cipherBlock cipher.Block, plainText []byte) ([]byte, error) {
	ciphertext := make([]byte, aes.BlockSize+len(plainText))
	initializationVector := ciphertext[:aes.BlockSize]
	_, err := io.ReadFull(rand.Reader, initializationVector)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(cipherBlock, initializationVector)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plainText)
	return ciphertext, nil
}
