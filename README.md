# trust

#### 介绍:
```
一个简单的高性能的认证模块, 防止接口完全公开被无脑调用

适用于内网, 低延时,可信度较高环境中的同一套服务的内部使用
仅需要使用统一的 KEY, 做简单的类似防盗链的加密认证方式

Decode 系列函数返回两个结果, 是否验证通过和错误码,
当通过当时候, 错误码为 nil, 不通过原因可通过错误码获得
其中 NoErr 系列只返回是否验证通过

Encode 系列函数需要注意, 当使用返回两个结果的函数时候,
其返回的密钥串中不包含时间戳信息
```

#### 特点:
1. 性能极高, 获取认证串仅耗时 95ns, 验证是否合法耗时约 300-400ns
2. 线程安全

#### Example
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
#### Benchmark

```
BenchmarkDecodeOne-4              	 2788777	       424.7 ns/op
BenchmarkDecodeOneNoErr-4         	 2813392	       425.2 ns/op
BenchmarkDecodeAtIntT-4           	 3227451	       372.7 ns/op
BenchmarkDecodeAtIntTNoErr-4      	 3134587	       377.9 ns/op
BenchmarkDecodeAtStringT-4        	 3515676	       341.1 ns/op
BenchmarkDecodeAtStringTNoErr-4   	 3550251	       337.5 ns/op
BenchmarkEncodeOne-4              	11798652	        94.49 ns/op
BenchmarkEncodeAtIntT-4           	12508225	        95.14 ns/op
BenchmarkEncodeStringT-4          	12508938	        94.23 ns/op
```