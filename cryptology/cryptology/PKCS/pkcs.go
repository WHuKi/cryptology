package PKCS

import "bytes"

//对最后一个分组进行填充
func Padding(src []byte,bits int) []byte  {
	//获取总长度
	length := len(src)
	//查看最后一位是多少
	n :=bits - length%bits
	//对最后的分组进行填充
	tail := bytes.Repeat([]byte{byte(n)},n)
	//将填充后的字节分组追加到最后
	pailText := append(src,tail...)
	return pailText
}

//去除最后分组填充的字母
func UnPadding(src []byte) []byte {
	//获取总长度
	length := len(src)
	//获取最后一个字节的值
	m := src[length-1]
	//将最后添加上字节值及进行去除
	return  src[:length-int(m)]
}
