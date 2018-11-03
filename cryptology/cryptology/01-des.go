package main

import (
	"crypto/des"
	"EmpeoymentClass/cryptology/PKCS"
	"crypto/cipher"
	"fmt"
)

func main()  {
	Str := "你好，我就未来"
	cipherText := Cipher_DES_CBC([]byte(Str),[]byte("12345678"))
	fmt.Println("加密后的密文",string(cipherText))

	text := DCipher_DES_CBC(cipherText,[]byte("12345678"))
	fmt.Println("解密后的明文：",string(text))
}
//使用des进行加密
func Cipher_DES_CBC(src,key []byte) []byte  {
	//创建一个使用des算法的接口
	block,err := des.NewCipher(key)
	if err != nil{
		panic(err)
	}
	//对最后一个分组进行填充
	pailText := PKCS.Padding(src,block.BlockSize())
	//使用CBC分组模式进行加密，使用明文的前八位进行初始化变量
	blockMode := cipher.NewCBCEncrypter(block,key[:block.BlockSize()])
	//加密
	cipherText := make([]byte,len(pailText))
	blockMode.CryptBlocks(cipherText,pailText)
	return cipherText
}
//使用des进行解密
func DCipher_DES_CBC(src,key []byte) []byte  {
	//创建一个使用des加密的接口
	block,err := des.NewCipher(key)
	if err != nil{
		panic(err)
	}
	//选择一个CBC模式进行加密
	blockMode := cipher.NewCBCDecrypter(block,key[:block.BlockSize()])
	//解密
	pailText := make([]byte,len(src))
	blockMode.CryptBlocks(pailText,src)
	//将最后一个分组追加的去除
	pailText = PKCS.UnPadding(pailText)
	return pailText
}