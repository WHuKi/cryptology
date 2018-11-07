package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

func main()  {
	sendHmac := GenerateMac([]byte("你好，我是未来"),[]byte("12345678asdfghjk"))

	is := VerifyHMAC(sendHmac,[]byte("你好，我是未来"),[]byte("12345678asdfghjk"))
	if is {
		fmt.Println("一致")
	}else {
		fmt.Println("不一致")
	}
}
//生成消息验证码
func GenerateMac(src,key []byte) []byte  {
	//1.创建一个采用sha256的消息验证码
	myhmac := hmac.New(sha256.New,key)
	//2.写入
	//myhmac.Write(src)
	//3.计算结果
    result :=	myhmac.Sum(src)
	return result
}

//验证消息验证码
func VerifyHMAC(res,src,key []byte) bool  {
	//1，创建一个采用sha256的接口
	myhmac := hmac.New(sha256.New,key)
	//2.计算哈希值
	//2.写入
	//myhmac.Write(src)
	verifyHmac := myhmac.Sum(src)
	//3.验证是否一致
	isTrue := hmac.Equal(res,verifyHmac)
	return isTrue
}
