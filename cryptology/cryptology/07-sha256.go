package main

import (
	"fmt"
	"crypto/sha256"
	"os"
	"io"
	"encoding/hex"
)

func main()  {
	hashVlue := Sha256_Encrypt("./public.pem")
	fmt.Println("哈希值：",hashVlue)
}
//使用sha256加密
func Sha256_Encrypt(filename string) string {
	//1,创建一个sha256的接口
	sha := sha256.New()
	//2,将明文内容写入到sha当中
	file,err := os.Open(filename)
	defer file.Close()
	if err != nil{
		panic(err)
	}
	buf := make([]byte,4096)
	for{
		n,err :=file.Read(buf)
		if err != nil && err == io.EOF{
			break
		}
		sha.Write(buf[:n])

	}
	tmp := sha.Sum(nil)
	//3,将哈希值进行hex处理
	res := hex.EncodeToString(tmp)
	return res
}
