package dll类

import (
	"fmt"
	"testing"
)

func TestNewDll(t *testing.T) {
	dll, err := I创建_快捷("user32.dll")
	if dll == nil {
		fmt.Println(err)
		return
	}

	ret, err := dll.I调用("MessageBoxW", 0, "hello", "world", 3)
	fmt.Println(ret, err)

	ret, err = dll.I调用("MessageBoxW", 0, "hello2", "world2", 3)
	fmt.Println(ret, err)

	dll.I卸载()
	ret, err = dll.I调用("MessageBoxW", 0, "hello2", "world2", 3)
	fmt.Println(ret, err)

	if err != nil && &ret.Errno == nil {
		t.Error("执行失败.")
	}
}
