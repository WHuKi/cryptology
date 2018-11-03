package main

import (
	"os"
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	"crypto/rand"
	"fmt"
)

func main()  {
	Str := "你好，我是未来"
	cipherText := RSA_Encrypt([]byte(Str),[]byte("public.pem"))
	fmt.Println("加密后的密文：",string(cipherText))

	text := RSA_Dncrypt(cipherText,[]byte("private.pem"))
	fmt.Println("解密后的明文：",string(text))
}

//使用RSA进行加密
func RSA_Encrypt(src,filename []byte) []byte  {
	//1，打开文件
	file,err := os.Open(string(filename))
	if err != nil{
		panic(err)
	}
	defer file.Close()
	//2,读取文件内容
	fileInfo,err := file.Stat()
	if err != nil{
		panic(err)
	}
	allText := make([]byte,fileInfo.Size())
	file.Read(allText)
	//3,从数据块当中找到下一个pem块,进行解码
	block,_ := pem.Decode(allText)
	if block == nil{
		return nil
	}
	//4,将序列化的公钥进行解析
	publicInterface ,err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil{
		panic(err)
	}
	publicKey := publicInterface.(*rsa.PublicKey)
	//5，加密
	result,_ := rsa.EncryptPKCS1v15(rand.Reader,publicKey,src)
	return result
}
//使用RSA进行解密
func RSA_Dncrypt(src,filename []byte) []byte  {
	//1，打开文件
	file,err := os.Open(string(filename))
	if err != nil{
		panic(err)
	}
	defer file.Close()
	//2,读取文件
	fileInfo,err := file.Stat()
	if err != nil{
		panic(err)
	}
	allText := make([]byte,fileInfo.Size())
	file.Read(allText)
	//3，从数据块当中查找下一个pem进行解码
	block,_ := pem.Decode(allText)
	if block==nil{
		return nil
	}
	//4，将私钥进行解析
    privateKey,err :=	x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil{
    	panic(err)
	}
	//5,解密
	result,_ := rsa.DecryptPKCS1v15(rand.Reader,privateKey,src)
	return result
}