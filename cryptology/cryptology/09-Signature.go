package main

import (
	"os"
	"encoding/pem"
	"crypto/x509"
	"crypto/sha256"
	"crypto/rsa"
	"crypto/rand"
	"crypto"
	"fmt"
)

func main()  {
	str := "你好，我是未来"
	sing := SignatureRSA(str,"private.pem")
	VerifySignature(str,"public.pem",sing)
}
//使用sha256生成签名
func SignatureRSA(src,filename string) []byte {
	//1.从密钥文件中读取内容
	fp,err := os.Open(filename)
	if err != nil{
		panic(err)
	}
	defer fp.Close()
	fileInfo,err := fp.Stat()
	buf := make([]byte,fileInfo.Size())
	fp.Read(buf)
	//2.将消息解析为pem格式
	block,_ := pem.Decode(buf)
	//3.解析pem数据块，得到私钥
	prevKey,_ := x509.ParsePKCS1PrivateKey(block.Bytes)
	//4.使用rsa256进行加密
	myHash := sha256.New()
	result := myHash.Sum([]byte(src))
	//5.生成签名
	mySinature,_:= rsa.SignPKCS1v15(rand.Reader,prevKey,crypto.SHA256,result)
	return mySinature
}
//验证签名
func VerifySignature(src, filename string,sing []byte)  {
	//1.打开文件
	file,err := os.Open(filename)
	if err != nil{
		panic(err)
	}
	defer file.Close()
	fileInfo,_ := file.Stat()
	buf := make([]byte,fileInfo.Size())
	file.Read(buf)
	//2.从pem中读取数据块
	block ,_ := pem.Decode(buf)
	//3.蒋公钥从pem块当中读取出来
	pubKey ,_:=x509.ParsePKIXPublicKey(block.Bytes)
	//4.将数据进行哈希计算
	myHash := sha256.New()
	result := myHash.Sum([]byte(src))
	//5.验证
	rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey),crypto.SHA256,result,sing)
	fmt.Println("签名验证成功")
}
