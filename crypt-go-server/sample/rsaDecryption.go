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
	"os"
)

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

func rsaDecrypt(in []byte, priv *rsa.PrivateKey) ([]byte, error) {
	sha1 := sha1.New()
	plainText, err := rsa.DecryptOAEP(sha1, rand.Reader, priv, in, nil)
	checkError(err)
	return plainText, nil
}

func main() {
	//open input file
	fi, err := os.OpenFile("testmovie.txt", os.O_RDONLY, 0)
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
	fo, err := os.Create("testmovie2.wmv")
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
	if err != nil {
		panic(err)
	}

	//make a buffer to keep chnks that are read
	buf := make([]byte, 256)
	i := 0
	for {
		n, err := r.Read(buf)
		if err != nil && err != io.EOF {
			panic(err)
		}
		if n == 0 {
			break
		}
		out, err := rsaDecrypt(buf[:n], privateKey)
		if err != nil {
			panic(err)
		}
		_, err = w.Write(out)
		if err != nil {
			panic(err)
		}
		i++

		//debug
		// fmt.Println("////////////////////   ", i, "   ////////////////////")
		// fmt.Println("InSize : ", len(buf[:n]))
		// fmt.Println("Plain : ", buf[:n])
		// fmt.Println("---------------------------------------------------------")
		// fmt.Println("OutSize : ", len(out))
		// fmt.Println("Decrypted : ", out)

	}
	if err = w.Flush(); err != nil {
		panic(err)
	}
}
