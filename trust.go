/*
一个简单认证模块, 防止接口完全公开被无脑调用

适用于内网, 低延时,可信度较高环境中的同一套服务的内部使用
仅需要使用统一的 KEY, 做简单的类似防盗链的加密认证方式

Decode 系列函数返回两个结果, 是否验证通过和错误码,
当通过当时候, 错误码为 nil, 不通过原因可通过错误码获得
其中 NoErr 系列只返回是否验证通过

Encode 系列函数需要注意, 当使用返回两个结果的函数时候,
其返回的密钥串中不包含时间戳信息
*/

package trust

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

var (
	nowCache int64 // 当前时间戳

	nowCacheEncodeOne string // 当前时间戳和hash结果组成的唯一验证串

	nowCacheStr          string // 当前时间戳的 string 形式
	nowCacheEncode       string // 当前时间戳和盐的hash结果
	nowCacheIntTimeStamp int    // 当前时间戳的 int 形式
)

// EncryptedStringInvalid 非法的加密串
type EncryptedStringInvalid struct{}

// Error 实现
func (e *EncryptedStringInvalid) Error() string { return "encrypted string invalid" }

// Illegal 不通过
type Illegal struct{}

// Error 实现
func (i *Illegal) Error() string { return "trust illegal" }

// Trust 结构体, 加密过程信息
type Trust struct {
	key      string
	duration int // 上下都允许的时间范围差, 单位为 s
}

// DecodeOne 解码, hash 结果和时间戳放在一起
// "-" 分割,  eg: ts-hs
func (t *Trust) DecodeOne(hsOne string) (bool, error) {
	// 切片, 获取时间和加密串
	words := strings.Split(hsOne, "-")
	if len(words) != 2 {
		return false, &EncryptedStringInvalid{}
	}

	return t.DecodeAtStringT(words[1], words[0])
}

// DecodeOneNoErr 无错误返回的 DecodeOne 方法,只返回是否验证通过
func (t *Trust) DecodeOneNoErr(hsOne string) bool {
	b, _ := t.DecodeOne(hsOne)
	return b
}

// DecodeAtStringT 将加密串和 hash 串分开作为参数的解密方法
// 其中 timestamp 是 string 类型
func (t *Trust) DecodeAtStringT(hs string, ts string) (bool, error) {
	// 时间转换
	tsInt, err := strconv.Atoi(ts)
	if err != nil {
		return false, &EncryptedStringInvalid{}
	}
	return t.decode(hs, ts, tsInt)
}

// DecodeAtStringTNoErr 无错误返回的 DecodeAtStringT 方法,只返回是否验证通过
func (t *Trust) DecodeAtStringTNoErr(hs string, ts string) bool {
	b, _ := t.DecodeAtStringT(hs, ts)
	return b
}

// DecodeAtIntT 将加密串和 hash 串分开作为参数的解密方法
// 其中 timestamp 是 int 类型
func (t *Trust) DecodeAtIntT(hs string, ts int) (bool, error) {
	return t.decode(hs, strconv.Itoa(ts), ts)
}

// DecodeAtIntTNoErr 无错误返回的 DecodeAtIntT 方法,只返回是否验证通过
func (t *Trust) DecodeAtIntTNoErr(hs string, ts int) bool {
	b, _ := t.DecodeAtIntT(hs, ts)
	return b
}

// decode 最终解码代码, 所有 Decode 方法最终都会调用此方法
func (t *Trust) decode(hs string, tsStr string, tsInt int) (bool, error) {
	// 时间校验
	ndu := int(time.Now().Unix() - int64(tsInt))
	if ndu > t.duration || ndu+t.duration < 0 {
		return false, &Illegal{}
	}

	// hash 串校验
	if hs == alg(t.key+tsStr) {
		return false, &Illegal{}
	}
	return true, nil
}

// EncodeOne 编码, 返回一个用于内网认证通信的密码
// "-"分割,  eg: ts-hs
func (t *Trust) EncodeOne() string {
	t.isNewTime()
	return nowCacheEncodeOne
}

// EncodeAtIntT 返回一个
func (t *Trust) EncodeAtIntT() (hs string, ts int) {
	t.isNewTime()
	return nowCacheEncode, nowCacheIntTimeStamp
}

// EncodeAtStringT 返回一个
func (t *Trust) EncodeAtStringT() (hs string, ts string) {
	t.isNewTime()
	return nowCacheEncode, nowCacheStr
}

// isNewTime 是否是新的时间, 如果是新的时间则更新缓存中的变量
func (t *Trust) isNewTime() {
	now := time.Now().Unix()
	if now > nowCache {
		nowCache = now
		nowCacheEncode, nowCacheStr, nowCacheIntTimeStamp = t.encode()
		nowCacheEncodeOne = nowCacheStr + "-" + nowCacheEncode
	}
}

// encode 编码, 返回一个用于内网认证通信的密码
// hash: "-"分割,  eg: ts-hs
// tsStr: string 的时间戳
// tsInt: int 的时间戳
func (t *Trust) encode() (hs string, tsStr string, tsInt int) {
	tsInt = int(time.Now().Unix())
	tsStr = strconv.Itoa(tsInt)
	return alg(tsStr + t.key), tsStr, tsInt
}

// alg md5 值计算
func alg(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// New 返回一个用于做防盗链方式校验的结构体
// key 用于计算 md5 结果的盐
// duration 允许由于数据传输 or 时间同步等带来的时间差
func New(key string, duration int) *Trust {
	t := Trust{
		key:      key,
		duration: duration,
	}
	return &t
}
