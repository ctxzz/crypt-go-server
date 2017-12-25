package main

import (
	"bufio"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"./crypto"

	"github.com/gin-gonic/gin"
)

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %s", err.Error())
		os.Exit(1)
	}
}

func main() {
	router := gin.Default()
	router.Static("/public", "public")
	router.Static("/videos", "videos")
	router.GET("/", helloWorld)
	router.GET("/app", sampleHTML)
	router.GET("/video/:name", videoFile)
	router.GET("/generateRSAKey", generateRSAKey)
	router.GET("/encrypt/hybrid/:name", encryptHybrid)
	router.GET("/streaming/hybrid/:name", streamHybridEncryptedVideo)
	// router.GET("/encrypt/rsa/:name", encryptRsa)
	// router.GET("/streaming/rsa/:name", streamRsaEncryptedVideo)
	router.GET("/streaming/original/:name", streamOriginalVideo)

	//error handler
	router.Use(func(c *gin.Context) {
		err := errors.New("Not Found")
		c.Error(err)
	})
	router.Run(":8080")
}

func helloWorld(c *gin.Context) {
	c.String(200, "hello world")
}

func sampleHTML(c *gin.Context) {
	c.File("public/sample.html")
}

func videoFile(c *gin.Context) {
	name := c.Param("name")
	file, err := os.OpenFile("/videos/"+name, os.O_RDONLY, 0)
	checkError(err)
	defer func() {
		file.Close()
	}()
	c.File("videos/" + name)
}

func generateRSAKey(c *gin.Context) {
	crypto.GenerateRSAKey()
}

func encryptHybrid(c *gin.Context) {
	name := c.Param("name")
	sha1 := sha1.New()
	//open Video file
	fi, err := os.OpenFile("videos/"+name, os.O_RDONLY, 0)
	checkError(err)
	defer func() {
		if err := fi.Close(); err != nil {
			panic(err)
		}
	}()
	r := bufio.NewReader(fi)
	fiInfo, err := fi.Stat()
	checkError(err)

	//open output file
	fo, err := os.Create(name + ".txt")
	checkError(err)
	defer func() {
		if err := fo.Close(); err != nil {
			panic(err)
		}
	}()
	w := bufio.NewWriter(fo)

	publicKey, err := crypto.ReadPublicKey("publicKey.pem")
	checkError(err)
	commonKey := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, commonKey)
	checkError(err)
	cryptoKey, err := rsa.EncryptOAEP(sha1, rand.Reader, publicKey, commonKey, nil)
	checkError(err)

	// //write commonkey to output
	// _, err = w.Write(publicKey.N.Bytes())
	// checkError(err)

	//write commonkey to output
	_, err = w.Write(cryptoKey)
	checkError(err)

	//write OriginalVideoSize
	videoSize := make([]byte, 10)
	binary.PutVarint(videoSize, fiInfo.Size())
	_, err = w.Write(videoSize)

	cipherBlock, err := aes.NewCipher(commonKey)
	checkError(err)
	buf := make([]byte, 16)
	for {
		n, err := r.Read(buf)
		if err != nil && err != io.EOF {
			panic(err)
		}
		if n == 0 {
			fmt.Println("finish encryt")
			break
		}
		out, err := crypto.AesEncrypt(cipherBlock, buf[:n])
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

func streamHybridEncryptedVideo(c *gin.Context) {
	name := c.Param("name")

	//file open
	fi, err := os.OpenFile(name, os.O_RDONLY, 0)
	checkError(err)
	defer func() {
		if err := fi.Close(); err != nil {
			panic(err)
		}
	}()
	r := io.ReadSeeker(fi)

	// read private key
	privateKey, err := crypto.ReadPrivateKey("privateKey.pem")
	checkError(err)

	// //read public Key
	// headerPublicKey := make([]byte, 256)
	// _, err = r.Read(headerPublicKey)
	// checkError(err)

	//read common key
	cryptoKey := make([]byte, 256)
	cryptoKeyLen, err := r.Read(cryptoKey)
	checkError(err)
	commonKey, err := crypto.RsaDecrypt(cryptoKey[:cryptoKeyLen], privateKey)
	checkError(err)
	cipherBlock, err := aes.NewCipher(commonKey)
	checkError(err)

	//read originalVideoSize
	orizinalVideoBuf := make([]byte, 10)
	orizinalVideoBufLen, err := r.Read(orizinalVideoBuf)
	orizinalVideoSize, _ := binary.Varint(orizinalVideoBuf[:orizinalVideoBufLen])
	req := c.Request
	w := c.Writer

	if req.Header.Get("range") != "" {
		rangeH := req.Header.Get("range")
		parts := strings.Split(strings.Replace(rangeH, "bytes=", "", -1), "-")
		partialstart := parts[0]
		partialend := parts[1]

		start, _ := strconv.Atoi(partialstart)
		end, _ := strconv.Atoi(partialend)
		if partialend == "" {
			end = int(orizinalVideoSize) - 1
			partialend = strconv.Itoa(end)
		}
		chunksize := (end - start) + 1
		rangeString := "bytes " + partialstart + "-" + partialend + "/" + strconv.FormatInt(orizinalVideoSize, 10)
		w.Header().Set("Content-Range", rangeString)
		w.Header().Set("Content-Length", strconv.Itoa(chunksize))
		w.Header().Set("Content-Type", "video/mp4")
		w.WriteHeader(206)
		//calculate seekPoint
		remainder16 := start % 16
		diffRemainder16 := start - remainder16
		seekPoint := diffRemainder16 * 2
		r.Seek(int64(seekPoint), 0)
	} else {
		w.Header().Set("Content-Length", strconv.FormatInt(orizinalVideoSize, 10))
		w.Header().Set("Content-Type", "video/mp4")
		w.WriteHeader(200)
	}

	buf := make([]byte, 32)
	for {
		n, err := r.Read(buf)
		if err != nil && err != io.EOF {
			panic(err)
		}
		if n == 0 {
			fmt.Println("decryption end!")
			break
		}

		out, err := crypto.AesDecrypt(cipherBlock, buf[:n])
		checkError(err)
		_, err = w.Write(out)
		if err != nil {
			panic(err)
		}
	}
	w.Flush()
}

// func encryptRsa(c *gin.Context) {
// 	name := c.Param("name")
//
// 	fi, err := os.OpenFile("videos/"+name, os.O_RDONLY, 0)
// 	checkError(err)
// 	defer func() {
// 		if err := fi.Close(); err != nil {
// 			panic(err)
// 		}
// 	}()
// 	r := bufio.NewReader(fi)
//
// 	fo, err := os.Create("testmovie.txt")
// 	checkError(err)
// 	defer func() {
// 		if err := fo.Close(); err != nil {
// 			panic(err)
// 		}
// 	}()
// 	w := bufio.NewWriter(fo)
//
// 	publicKey, err := crypto.ReadPublicKey("publicKey.pem")
// 	checkError(err)
//
// 	buf := make([]byte, 200)
// 	for {
// 		n, err := r.Read(buf)
// 		if err != nil && err != io.EOF {
// 			panic(err)
// 		}
// 		if n == 0 {
// 			break
// 		}
//
// 		out, err := crypto.RsaEncrypt(buf[:n], publicKey)
// 		checkError(err)
//
// 		if _, err := w.Write(out); err != nil {
// 			panic(err)
// 		}
// 	}
// 	if err = w.Flush(); err != nil {
// 		panic(err)
// 	}
// 	fmt.Println("encryptRSA end!")
// }
//
// func streamRsaEncryptedVideo(c *gin.Context) {
// 	name := c.Param("name")
//
// 	//file open
// 	fi, err := os.OpenFile(name+".txt", os.O_RDONLY, 0)
// 	checkError(err)
// 	defer func() {
// 		if err := fi.Close(); err != nil {
// 			panic(err)
// 		}
// 	}()
// 	r := bufio.NewReader(fi)
// 	// read private key
// 	privateKey, err := crypto.ReadPrivateKey("privateKey.pem")
// 	checkError(err)
//
// 	buf := make([]byte, 256)
// 	c.Stream(func(w io.Writer) bool {
// 		n, err := r.Read(buf)
// 		if err != nil && err != io.EOF {
// 			panic(err)
// 		}
//
// 		if n == 0 {
// 			fmt.Println("decryption end!")
// 			return false
// 		}
// 		out, err := crypto.RsaDecrypt(buf[:n], privateKey)
// 		checkError(err)
//
// 		_, err = w.Write(out)
// 		if err != nil {
// 			panic(err)
// 		}
//
// 		return true
// 	})
// }
//
func streamOriginalVideo(c *gin.Context) {
	name := c.Param("name")
	//file open
	fi, err := os.OpenFile("videos/"+name, os.O_RDONLY, 0)
	checkError(err)
	defer func() {
		if err := fi.Close(); err != nil {
			panic(err)
		}
	}()
	fiInfo, err := fi.Stat()
	checkError(err)
	fmt.Println(fiInfo.Size())
	r := io.ReadSeeker(fi)
	req := c.Request
	w := c.Writer

	if req.Header.Get("range") != "" {
		rangeH := req.Header.Get("range")
		parts := strings.Split(strings.Replace(rangeH, "bytes=", "", -1), "-")
		partialstart := parts[0]
		partialend := parts[1]

		start, _ := strconv.Atoi(partialstart)
		end, _ := strconv.Atoi(partialend)
		if partialend == "" {
			end = int(fiInfo.Size()) - 1
			partialend = strconv.Itoa(end)
		}
		chunksize := (end - start) + 1
		rangeString := "bytes " + partialstart + "-" + partialend + "/" + strconv.FormatInt(fiInfo.Size(), 10)
		w.WriteHeader(206)
		w.Header().Set("Content-Range", rangeString)
		w.Header().Set("Content-Length", strconv.Itoa(chunksize))
		w.Header().Set("Content-Type", "video/mp4")
		w.Header().Set("Accept-Ranges", "0-"+strconv.Itoa(int(fiInfo.Size())-1))
		r.Seek(int64(start), 0)
	} else {
		w.WriteHeader(200)
		w.Header().Set("Content-Length", strconv.FormatInt(fiInfo.Size(), 10))
		w.Header().Set("Content-Type", "video/mp4")
	}
	buf := make([]byte, 16)
	for {
		n, err := r.Read(buf)
		if err != nil && err != io.EOF {
			panic(err)
		}
		if n == 0 {
			fmt.Println("stream END")
			break
		}

		_, err = w.Write(buf[:n])
		if err != nil {
			panic(err)
		}
	}
	w.Flush()
}
