// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Windows系统调用。

package dll类

import (
	"math"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

type Handle uintptr

const InvalidHandle = ^Handle(0)

// StringToUTF16 返回UTF-8字符串s的UTF-16编码，
// 添加了终止NUL。 如果s包含NUL字节，则该函数会死机，而不是返回错误。
//
// 不推荐：改用UTF16FromString。
// Deprecated: Use UTF16FromString instead.
func StringToUTF16(s string) []uint16 {
	return syscall.StringToUTF16(s)
}

// UTF16FromString 返回UTF-8字符串的UTF-16编码，并添加终止NUL.
// 如果s在任何位置包含NUL字节，则返回（nil，EINVAL）。
func UTF16FromString(s string) ([]uint16, error) {
	return syscall.UTF16FromString(s)
}

// UTF16ToString 返回UTF-16序列的UTF-8编码，
// 去除了终止NUL。
func UTF16ToString(s []uint16) string {
	return syscall.UTF16ToString(s)
}

// StringToUTF16Ptr 返回指向UTF-8字符串的UTF-16编码的指针, 添加了终止NUL.
// 如果s包含NUL字节，则该函数会死机，而不是返回错误。
//
// 不推荐：改用UTF16TrFromString。
// Deprecated: Use UTF16PtrFromString instead.
func StringToUTF16Ptr(s string) *uint16 {
	return syscall.StringToUTF16Ptr(s)
}

// UTF16PtrFromString 返回指向UTF-8字符串的UTF-16编码的指针，并添加终止NUL.
// 如果s在任何位置包含NUL字节，则返回（nil，EINVAL）。
func UTF16PtrFromString(s string) (*uint16, error) {
	return syscall.UTF16PtrFromString(s)
}

// NewCallback 将Go函数转换为符合stdcall调用约定的函数指针。
// 这在与需要回调的Windows代码进行互操作时非常有用。
// 参数应为具有一个uintptr大小结果的函数.函数的参数大小不能大于uintptr的大小。
// 在一个Go进程中只能创建有限数量的回调，并且不会释放为这些回调分配的任何内存。
// 在NewCallback和NewCallbackCDecl之间，始终可以创建至少1024个回调。
func NewCallback(fn any) uintptr {
	return syscall.NewCallback(fn)
}

// NewCallbackCDecl 将Go函数转换为符合cdecl调用约定的函数指针。
// 这在与需要回调的Windows代码进行互操作时非常有用。
// 参数应为具有一个uintptr大小结果的函数. 函数的参数大小不能大于uintptr的大小。
// 在单个Go过程中只能创建有限数量的回调， 并且永远不会释放为这些回调分配的任何内存。
// 在NewCallback和NewCallbackCDecl之间，始终可以创建至少1024个回调。
func NewCallbackCDecl(fn any) uintptr {
	return syscall.NewCallbackCDecl(fn)
}

//以下是一些便捷的指针转换函数, 摘自 https://github.com/twgh/xcgui/tree/main/common

// I文本到指针 将string转换到uintptr.
// 已核对无误
func I文本到指针(s string) uintptr {
	if len(s) == 0 {
		return uintptr(0)
	}
	p, _ := syscall.UTF16PtrFromString(s)
	return uintptr(unsafe.Pointer(p))
}

type sliceHeader struct {
	Data uintptr
	Len  int
	Cap  int
}

// I指针到文本 将uintptr转换到string.
func I指针到文本(ptr uintptr) string {
	s := *(*[]uint16)(unsafe.Pointer(&ptr)) // uintptr转换到[]uint16
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			(*sliceHeader)(unsafe.Pointer(&s)).Cap = i // 修改切片的cap
			s = s[0:i]
			break
		}
	}
	return string(utf16.Decode(s))
}

// BoolPtr 将bool转换到uintptr.
// 已核对无误
func BoolPtr(b bool) uintptr {
	if b {
		return uintptr(1)
	}
	return uintptr(0)
}

// I指针到小数32   将uintptr转换到float32.
func I指针到小数32(ptr uintptr) float32 {
	//u := uint32(ptr)
	//return *(*float32)(unsafe.Pointer(&u))
	return math.Float32frombits(uint32(ptr)) //gosdk提供的方法
}

// I指针到小数64 将uintptr转换到float64.
func I指针到小数64(ptr uintptr) float64 {
	return math.Float64frombits(uint64(ptr)) //gosdk提供的方法
}

// I字节集到指针 将byte[0]指针转换到uintptr.
// 此处之所以要用指针参数,主要是考虑性能
// 已核对无误
func I字节集到指针(b *[]byte) uintptr {
	if len(*b) == 0 {
		return uintptr(0)
	}
	return uintptr(unsafe.Pointer(&(*b)[0]))
}

// Uint16SliceDataPtr 将uint16[0]指针转换到uintptr.
func Uint16SliceDataPtr(p *[]uint16) uintptr {
	if len(*p) == 0 {
		return uintptr(0)
	}
	return uintptr(unsafe.Pointer(&(*p)[0]))
}

// StringToUint16Ptr 返回指向 UTF-8 字符串 s 的 UTF-16 编码的指针，与 syscall.UTF16PtrFromString 不同的是末尾没有添加终止 NUL。
func StringToUint16Ptr(s string) *uint16 {
	return &utf16.Encode([]rune(s))[0]
}

// Uint16SliceToStringSlice 按null字符分割, 把 []uint16 转换到 []string.
func Uint16SliceToStringSlice(s []uint16) []string {
	strSlice := make([]string, 0)
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			strSlice = append(strSlice, string(utf16.Decode(s[start:i])))
			start = i + 1

			// 连续null字符, 所以跳出
			if s[start] == 0 {
				break
			}
		}
	}
	return strSlice
}
