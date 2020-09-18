package trust

import (
	"fmt"
	"strconv"
	"testing"
	"time"
)

var (
	t           *Trust
	TrueHash    string
	TrueIntT    int
	TrueStringT string
	TrueOne     string
)

func init() {
	t = New("hello trust", 60)
	TrueHash, TrueIntT = t.EncodeAtIntT()
	TrueStringT = strconv.Itoa(TrueIntT)
	TrueOne = TrueStringT + "-" + TrueHash
}

// BenchmarkDecodeOne xxx
func BenchmarkDecodeOne(b *testing.B) {
	for i := 0; i < b.N; i++ {
		t.DecodeOne(TrueOne)
	}
}

func BenchmarkDecodeOneNoErr(b *testing.B) {
	for i := 0; i < b.N; i++ {
		t.DecodeOneNoErr(TrueOne)
	}
}

func BenchmarkDecodeAtIntT(b *testing.B) {
	for i := 0; i < b.N; i++ {
		t.DecodeAtIntT(TrueHash, TrueIntT)
	}
}

func BenchmarkDecodeAtIntTNoErr(b *testing.B) {
	for i := 0; i < b.N; i++ {
		t.DecodeAtIntTNoErr(TrueHash, TrueIntT)
	}
}

func BenchmarkDecodeAtStringT(b *testing.B) {
	for i := 0; i < b.N; i++ {
		t.DecodeAtStringT(TrueHash, TrueStringT)
	}
}

func BenchmarkDecodeAtStringTNoErr(b *testing.B) {
	for i := 0; i < b.N; i++ {
		t.DecodeAtStringTNoErr(TrueHash, TrueStringT)
	}
}

func BenchmarkEncodeOne(b *testing.B) {
	for i := 0; i < b.N; i++ {
		t.EncodeOne()
	}
}

func BenchmarkEncodeAtIntT(b *testing.B) {
	for i := 0; i < b.N; i++ {
		t.EncodeAtIntT()
	}
}

func BenchmarkEncodeStringT(b *testing.B) {
	for i := 0; i < b.N; i++ {
		t.EncodeAtStringT()
	}
}

func Example() {
	tru := New("hello world, hello trust", 2)
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
