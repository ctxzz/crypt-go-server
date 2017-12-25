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

func readPrivateKey(path string) (*rsa.PrivateKey, error) {
	privateKeyData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	privateKeyBlock, _ := pem.Decode([]byte(privateKeyData))
	if privateKeyBlock == nil {
		return nil, errors.New("bad private key data")
	}
	if privateKeyBlock.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("unknown key type : %s", privateKeyBlock.Type)
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func decrypt(cipherBlock cipher.Block, cipherText []byte) ([]byte, error) {
	plainText := make([]byte, len(cipherText)-aes.BlockSize)
	stream := cipher.NewCTR(cipherBlock, cipherText[:aes.BlockSize])
	stream.XORKeyStream(plainText, cipherText[aes.BlockSize:len(cipherText)])
	return plainText, nil
}

func main() {
	sha1 := sha1.New()

	//open input file
	fi, err := os.OpenFile("hybrid.txt", os.O_RDONLY, 0)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := fi.Close(); err != nil {
			panic(err)
		}
	}()
	//make a read buffer
	r := bufio.NewReader(fi)

	//open output file
	fo, err := os.Create("hybrid.wmv")
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := fo.Close(); err != nil {
			panic(err)
		}
	}()
	//make a write buffer
	w := bufio.NewWriter(fo)

	// read private key
	privateKey, err := readPrivateKey("privateKey.pem")
	checkError(err)

	//read publickey and common key
	headPublicKey := make([]byte, 256)
	_, err = r.Read(headPublicKey)
	checkError(err)
	cryptoKey := make([]byte, 256)
	cryptoKeyLen, err := r.Read(cryptoKey)
	checkError(err)
	commonKey, err := rsa.DecryptOAEP(sha1, rand.Reader, privateKey, cryptoKey[:cryptoKeyLen], nil)
	checkError(err)
	cipherBlock, err := aes.NewCipher(commonKey)
	checkError(err)

	buf := make([]byte, 32)
	for {
		n, err := r.Read(buf)
		if err != nil && err != io.EOF {
			panic(err)
		}
		if n == 0 {
			break
		}

		out, err := decrypt(cipherBlock, buf[:n])
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
