package main

import (
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func main()  {
	RsaGenKey(1024)
}

func RsaGenKey(bits int)  {
	//========生成私钥========
	//1，使用rsa接口
	privateKey,err := rsa.GenerateKey(rand.Reader,bits)
	if err != nil{
		panic(err)
	}
	//2，使用x509将私钥进行编码
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	//3，使用pem进行编码
	privateFile,err := os.Create("private.pem")
	if err != nil{
		panic(err)
	}
	defer privateFile.Close()
	block := pem.Block{
		Type:"RSA PRIVATE KEY",
		Bytes:derStream,
	}
	err = pem.Encode(privateFile,&block)
	if err != nil{
		panic(err)
	}
	//==========公钥=============
	//1生成公钥
	publicKey := privateKey.PublicKey
	//2,对公钥进行编码
	detStream,err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil{
		panic(detStream)
	}
	//3,将公钥写入到文件当中
	publicFile,err := os.Create("public.pem")
	if err != nil{
		panic(err)
	}
	block = pem.Block{
		Type:"RSA PUBLIC KEY",
		Bytes:detStream,
	}
	defer publicFile.Close()
	err = pem.Encode(publicFile,&block)
	if err != nil{
		panic(err)
	}
}
