package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"EmpeoymentClass/cryptology/PKCS"
)

func main()  {
	Str := "你好，我是未来"
	cipherText := Cipher_AES_CBC([]byte(Str),[]byte("zxcvbnmk12345678"))
	fmt.Println("加密后的密文：",string(cipherText))
	text := Dcipher_AES_CBC(cipherText,[]byte("zxcvbnmk12345678"))
	fmt.Println("解密后的密文：",string(text))
}
//使用aes进行加密
func  Cipher_AES_CBC(src,key []byte) []byte  {
	//创建一个aes的接口
	block,err := aes.NewCipher(key)
	if err != nil{
		panic(err)
	}
	cipherText := PKCS.Padding(src,block.BlockSize())
	//选择迭代模式
	blockMode := cipher.NewCBCEncrypter(block,key[:block.BlockSize()])
	//加密
	pailText := make([]byte,len(cipherText))
	blockMode.CryptBlocks(pailText,cipherText)
	return pailText
}
//使用aes进行解密
func Dcipher_AES_CBC(src,key []byte) []byte  {
	//创建一个使用aes的接口
	block,err:= aes.NewCipher(key)
	if err != nil{
		panic(err)
	}
	//选择迭代的模式
	blockMode := cipher.NewCBCDecrypter(block,key[:block.BlockSize()])
	//解密
	text := make([]byte,len(src))
	blockMode.CryptBlocks(text,src)
	text = PKCS.UnPadding(text)
	return text
}
