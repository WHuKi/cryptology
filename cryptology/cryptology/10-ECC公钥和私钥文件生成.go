package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func main()  {
	GenerateEccKey()
}

//使用ECC加密算法生成公钥和私钥
func GenerateEccKey()  {
	///////////////生成ECC私钥文件//////////////////
	//1.生成私钥
	privateKey,_ := ecdsa.GenerateKey(elliptic.P521(),rand.Reader)
	//2.将密钥进行x509编码
	x509PrivateKey ,_ := x509.MarshalECPrivateKey(privateKey)
	//3.使用pem进行快编码
	block := pem.Block{
		Type:"ECC PRIVATE KEY",
		Bytes:x509PrivateKey,
	}
	//4.将密钥写入到文件当中
	filePrivate,_ := os.Create("eccprivate.pem")
	pem.Encode(filePrivate,&block)

	///////////////生成ECC公钥文件//////////////////
	//1.生成公钥
	x509publicKey,_ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	//2.使用pem进行块编码
	pubBlock := pem.Block{
		Type:"ECC PUBLIC KEY",
		Bytes:x509publicKey,
	}
	//3.将公钥写入到文件当中
	filePublic,_ := os.Create("eccpublic.pem")
	pem.Encode(filePublic,&pubBlock)
}
