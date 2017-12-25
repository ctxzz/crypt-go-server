package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

func readPublicKey(path string) (*rsa.PublicKey, error) {
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

func rsaEncrypt(in []byte, pub *rsa.PublicKey) ([]byte, error) {
	sha1 := sha1.New()
	out, err := rsa.EncryptOAEP(sha1, rand.Reader, pub, in, nil)
	if err != nil {
		log.Fatalf("Failed to encrypt message %v", err)
		return nil, err
	}
	return out, nil
}

func main() {
	//open input file
	fi, err := os.OpenFile("videos/testmovie.mp4", os.O_RDONLY, 0)
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
	fo, err := os.Create("testmovie.txt")
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

	// read public key
	publicKey, err := readPublicKey("publicKey.pem")
	if err != nil {
		panic(err)
	}

	//make a buffer to keep chnks that are read
	buf := make([]byte, 200)
	i := 0
	for {
		n, err := r.Read(buf)
		if err != nil && err != io.EOF {
			panic(err)
		}
		if n == 0 {
			break
		}

		out, err := rsaEncrypt(buf[:n], publicKey)
		if err != nil {
			panic(err)
		}

		if _, err := w.Write(out); err != nil {
			panic(err)
		}
		i++

		//debug
		fmt.Println("////////////////////   ", i, "   ////////////////////")
		fmt.Println("InSize : ", len(buf[:n]))
		fmt.Println("Plain : ", buf[:n])
		fmt.Println("-----")
		fmt.Println("OutSize : ", len(out))
		fmt.Println("Encrypted : ", out)
	}
	if err = w.Flush(); err != nil {
		panic(err)
	}
}
