package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"fmt"
	"os"
)

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %s", err.Error())
		os.Exit(1)
	}
}

func RsaDecrypt(in []byte, priv *rsa.PrivateKey) ([]byte, error) {
	sha1 := sha1.New()
	plainText, err := rsa.DecryptOAEP(sha1, rand.Reader, priv, in, nil)
	checkError(err)
	return plainText, nil
}

func AesDecrypt(cipherBlock cipher.Block, cipherText []byte) ([]byte, error) {
	plainText := make([]byte, len(cipherText)-aes.BlockSize)
	stream := cipher.NewCTR(cipherBlock, cipherText[:aes.BlockSize])
	stream.XORKeyStream(plainText, cipherText[aes.BlockSize:len(cipherText)])
	return plainText, nil
}
