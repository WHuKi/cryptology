package main

import (
	"os"
	"encoding/pem"
	"crypto/x509"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/rand"
	"math/big"
	"fmt"
)

func main()  {
	rText,sText := Ecc_Sign("你好，我是未来","eccprivate.pem")
	is := Ecc_Verify("你好，我是未来","eccpublic.pem",rText,sText)
	if is {
		fmt.Println("一致")
	}else {
		fmt.Println("不一致")
	}
}
//使用ECC生成签名
func Ecc_Sign(src,filename string) ([]byte,[]byte)  {
	//1.获取私钥
	privateKey := GetPrivateKey(filename)
	//2.将消息生成哈希值
	myhash := sha256.New()
	resultHash := myhash.Sum([]byte(src))
	//3.使用私钥对任意长度的私钥生成一致的签名
	r,s,_:= ecdsa.Sign(rand.Reader,privateKey,resultHash)
	rText,_ := r.MarshalText()
	sText,_ := s.MarshalText()
	return rText,sText
}
//使用ECC验证签名
func Ecc_Verify(src,filename string,rText,sText []byte) bool {
	//1.获取公钥
	publicKey := GetPublickey(filename)
	//2.将消息生成哈希值
	myhash := sha256.New()
	resultHash := myhash.Sum([]byte(src))
	//3.验证签名
	var r,s big.Int
	r.UnmarshalText(rText)
	s.UnmarshalText(sText)

	is := ecdsa.Verify(publicKey,resultHash,&r,&s)
	return is
}

//获取私钥
func GetPrivateKey(filename string) *ecdsa.PrivateKey {
	file,_:= os.Open(filename)
	defer file.Close()
	fileInfo,_:= file.Stat()
	buf := make([]byte,fileInfo.Size())
	file.Read(buf)
	//将内容进行pem解码
	block ,_ := pem.Decode(buf)
	//将block解码
	privateKey,_ := x509.ParseECPrivateKey(block.Bytes)
	return privateKey
}

//获取公钥
func GetPublickey(filename string) *ecdsa.PublicKey  {
	file,_ := os.Open(filename)
	defer file.Close()
	fileInfo,_ := file.Stat()
	buf := make([]byte,fileInfo.Size())
	file.Read(buf)
	//将内容进行pem解码
	block,_ := pem.Decode(buf)
	//将block解码
	publicKey,_ := x509.ParsePKIXPublicKey(block.Bytes)
	return publicKey.(*ecdsa.PublicKey)
}