# trust

```
一个简单认证模块, 防止接口完全公开被无脑调用

适用于内网, 低延时,可信度较高环境中的同一套服务的内部使用
仅需要使用统一的 KEY, 做简单的类似防盗链的加密认证方式

Decode 系列函数返回两个结果, 是否验证通过和错误码,
当通过当时候, 错误码为 nil, 不通过原因可通过错误码获得
其中 NoErr 系列只返回是否验证通过

Encode 系列函数需要注意, 当使用返回两个结果的函数时候,
其返回的密钥串中不包含时间戳信息
```

```

func Example() {
	tru := New("hello world, hello trust", 2) // 单位为 s
	hashOne := tru.EncodeOne()

	time.Sleep(time.Duration(1) * time.Second)
	s1, e1 := tru.DecodeOne(hashOne)

	time.Sleep(time.Duration(2) * time.Second)
	s2, e2 := tru.DecodeOne(hashOne)

	if s1 && e1 == nil && !s2 && e2 != nil {
		fmt.Println("Good")
	} else {
		fmt.Println("Bad")
	}
	// output: Good
}

```
