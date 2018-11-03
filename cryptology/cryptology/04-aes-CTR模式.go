package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main()  {
	Str := "你好，我是未来"
	cipherText := CipherAndDcipher_AES_CTR([]byte(Str),[]byte("12345678asdfghjk"))
	fmt.Println("加密后的密文：",string(cipherText))
	//解密后的密文
	text := CipherAndDcipher_AES_CTR(cipherText,[]byte("12345678asdfghjk"))
	fmt.Println("解密后的密文是：",string(text))
}
//使用aes进行加密，迭代模式选择CTR
func CipherAndDcipher_AES_CTR(src,key []byte) []byte  {
	//选择aec进行加密
	block ,err := aes.NewCipher(key)
	if err != nil{
		panic(err)
	}
	//选择CTR模式进行迭代
	vi := []byte("zxcvbnmkasdfghjk")
	blockMode := cipher.NewCTR(block,vi)
	//加密
	pailText := make([]byte,len(src))
	blockMode.XORKeyStream(pailText,src)
	return pailText
}
