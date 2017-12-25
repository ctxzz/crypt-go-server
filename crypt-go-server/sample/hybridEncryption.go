package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %s", err.Error())
		os.Exit(1)
	}
}

func readPublicKey(path string) (*rsa.PublicKey, error) {
	publicKeyData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	publicKeyBlock, _ := pem.Decode([]byte(publicKeyData))
	if publicKeyBlock == nil {
		return nil, errors.New("bad public key data")
	}
	if publicKeyBlock.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unknown key type : %s", publicKeyBlock.Type)
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not RSA public key")
	}
	return publicKey, nil
}

func encrypt(cipherBlock cipher.Block, plainText []byte) ([]byte, error) {
	ciphertext := make([]byte, aes.BlockSize+len(plainText))
	initializationVector := ciphertext[:aes.BlockSize]
	_, err := io.ReadFull(rand.Reader, initializationVector)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(cipherBlock, initializationVector)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plainText)
	return ciphertext, err
}

func main() {
	sha1 := sha1.New()

	fi, err := os.OpenFile("videos/testmovie.mp4", os.O_RDONLY, 0)
	checkError(err)
	defer func() {
		if err := fi.Close(); err != nil {
			panic(err)
		}
	}()
	r := bufio.NewReader(fi)

	//open output file
	fo, err := os.Create("hybrid.txt")
	checkError(err)
	defer func() {
		if err := fo.Close(); err != nil {
			panic(err)
		}
	}()
	w := bufio.NewWriter(fo)

	publicKey, err := readPublicKey("publicKey.pem")
	checkError(err)
	commonKey := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, commonKey)
	checkError(err)
	cryptoKey, err := rsa.EncryptOAEP(sha1, rand.Reader, publicKey, commonKey, nil)
	checkError(err)

	//write publickey commonkey
	w.Write(publicKey.N.Bytes())
	w.Write(cryptoKey)

	cipherBlock, err := aes.NewCipher(commonKey)
	checkError(err)

	//make a buffer to keep chnks that are read
	buf := make([]byte, 16)
	for {
		n, err := r.Read(buf)
		if err != nil && err != io.EOF {
			panic(err)
		}
		if n == 0 {
			break
		}

		out, err := encrypt(cipherBlock, buf[:n])
		checkError(err)
		_, err = w.Write(out)
		if err != nil {
			panic(err)
		}
	}
	if err = w.Flush(); err != nil {
		panic(err)
	}
}
