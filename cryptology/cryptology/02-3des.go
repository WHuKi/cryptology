package main

import (
	"crypto/des"
	"EmpeoymentClass/cryptology/PKCS"
	"crypto/cipher"
	"fmt"
)

func main()  {
	Str := "你好，我是未来"
	cipherText := Cipher_3DES_CBC([]byte(Str),[]byte("12345678asdfghjkzxcvbnmk"))
	fmt.Println("加密后的密文：",string(cipherText))
	text := Dcipher_3DES_CBC(cipherText,[]byte("12345678asdfghjkzxcvbnmk"))
	fmt.Println("解密后的密文：",string(text))
}

//使用3des进行加密
func Cipher_3DES_CBC(src,key []byte) []byte  {
	//创建一个调用3des的接口
	block,err := des.NewTripleDESCipher(key)
	if err != nil{
		panic(err)
	}
	//对最后一组进行填充
	pailText := PKCS.Padding(src,block.BlockSize())
	//选择CBC模式进行迭代
	blockMode := cipher.NewCBCEncrypter(block,key[:block.BlockSize()])
	//解密
	cipherText := make([]byte,len(pailText))
	blockMode.CryptBlocks(cipherText,pailText)
	return cipherText
}
//使用3des进行解密
func Dcipher_3DES_CBC(src,key []byte) []byte  {
	//创建一个3des加密的接口
	block,err := des.NewTripleDESCipher(key)
	if err != nil{
		panic(err)
	}
	//选择迭代的模式进行迭代
	blockMode := cipher.NewCBCDecrypter(block,key[:block.BlockSize()])
	//解密
	pailText := make([]byte,len(src))
	blockMode.CryptBlocks(pailText,src)
	//将最后一个分组填充的进行去除
	pailText = PKCS.UnPadding(pailText)
	return pailText
}
