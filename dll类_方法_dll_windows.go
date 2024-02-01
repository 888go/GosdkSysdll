// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package dll类 备注, 由go的syscall包复制过来修改的.
package dll类

import (
	"errors"
	"syscall"
)

// I调用命令3 不推荐：改用SyscallN。
// Deprecated: Use I调用命令 instead.
func I调用命令3(命令地址, 参数个数, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return syscall.Syscall(命令地址, 参数个数, a1, a2, a3)
}

// I调用命令6 不推荐：改用SyscallN。
// Deprecated: Use I调用命令 instead.
func I调用命令6(命令地址, 参数个数, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return syscall.Syscall6(命令地址, 参数个数, a1, a2, a3, a4, a5, a6)
}

// I调用命令9 不推荐：改用SyscallN。
// Deprecated: Use I调用命令 instead.
func I调用命令9(命令地址, 参数个数, a1, a2, a3, a4, a5, a6, a7, a8, a9 uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return syscall.Syscall9(命令地址, 参数个数, a1, a2, a3, a4, a5, a6, a7, a8, a9)
}

// I调用命令12 不推荐：改用SyscallN。
// Deprecated: Use I调用命令 instead.
func I调用命令12(命令地址, 参数个数, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12 uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return syscall.Syscall12(命令地址, 参数个数, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12)
}

// I调用命令15 不推荐：改用SyscallN。
// Deprecated: Use I调用命令 instead.
func I调用命令15(命令地址, 参数个数, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15 uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return syscall.Syscall15(命令地址, 参数个数, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15)
}

// Deprecated: Use I调用命令 instead.
// I调用命令18 不推荐：改用SyscallN。
func I调用命令18(命令地址, 参数个数, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18 uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return syscall.Syscall18(命令地址, 参数个数, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18)
}

func I调用命令(命令地址 uintptr, 命令参数s ...uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return syscall.SyscallN(命令地址, 命令参数s...)
}

// DLL 实现对DLL的访问。
type DLL struct {
	DLL父类 syscall.DLL
}

// I创建 将命名的DLL文件加载到内存中。
// 如果"dll名称"不是绝对路径，也不是Go使用的已知系统DLL，
// Windows将在许多位置搜索命名的DLL，从而导致潜在的DLL预加载攻击。
// 使用golang.org/x/sys/windows中的LazyDLL可以安全地加载系统DLL。
func I创建(dll名称 string) (*DLL, error) {
	返回, err := syscall.LoadDLL(dll名称)
	if 返回 == nil {
		return nil, err
	}
	return &DLL{*返回}, nil
}

// I创建P 类似于LoadDLL，但在加载操作失败时会panic。
func I创建P(dll名称 string) *DLL {
	返回 := syscall.MustLoadDLL(dll名称)
	if 返回 == nil {
		return nil
	}
	return &DLL{*返回}
}

// I查找命令 在DLL d中搜索名为 "dll名称"，如果找到则返回*Proc。如果搜索失败，则返回错误。
func (d *DLL) I查找命令(命令名 string) (proc *Proc, err error) {
	if d == nil {
		return nil, errors.New("dll类对象为nil")
	}
	返回, err := d.DLL父类.FindProc(命令名)
	if 返回 == nil {
		return nil, err
	}
	return &Proc{*返回}, err
}

// I查找命令P 与FindProc类似，但如果搜索失败则会恐慌。
func (d *DLL) I查找命令P(命令名 string) *Proc {
	if d == nil {
		return nil
	}
	返回 := d.DLL父类.MustFindProc(命令名)
	if 返回 == nil {
		return nil
	}
	return &Proc{*返回}
}

// I卸载dll 从内存中卸载DLL 。
func (d *DLL) I卸载dll() (err error) {
	if d == nil {
		return errors.New("dll类对象为nil")
	}
	return d.DLL父类.Release()
}

// A Proc 实现对DLL内部命令的访问。
type Proc struct {
	Proc父类 syscall.Proc
}

// I取命令地址 返回dll内命令的地址。
// 返回值可以传递给 "I调用命令" 以调用命令。
func (p *Proc) I取命令地址() uintptr {
	if p == nil {
		return 0
	}
	return p.Proc父类.Addr()
}

// I调用 使用参数a执行过程p。
//
// 返回的错误总是非nil，由GetLastError的结果构造。
// 调用方必须检查主返回值，以确定是否发生了错误（根据所调用的特定函数的语义），然后才能查看错误。
// 错误的类型始终为syscall.Errno。
//
// 在amd64上, 调用可以传递和返回浮点值(Float32/Float64).
// 要传递C类型为“float”的参数x， 使用uintptr(math.Float32bits(x)).
// 传递C类型为“double”的参数，使用uintptr(math.Float64bits(x)).
//
// 在r2中返回浮点返回值
// C类型“float”的返回值为math.Float32frombits(uint32(r2)).
// 对于C类型“double”，返回值为 math.Float64frombits(uint64(r2)).
// 2023-01-28 备注,网上有人说接收返回的浮点值, 应该用第二个返回值 r2
func (p *Proc) I调用(命令参数s ...uintptr) (uintptr, uintptr, error) {
	if p == nil {
		return 0, 0, errors.New("dll类对象为nil")
	}
	return p.Proc父类.Call(命令参数s...)
}

// A LazyDLL 实现对单个DLL的访问。
// 它将延迟DLL的加载，直到第一次调用其" I取模块地址() " 方法或LazyProc的 "I取命令地址()" 方法。
//
// LazyDLL容易受到与LoadDLL中记录的相同的DLL预加载攻击。
// 使用golang.org/x/sys/windows中的LazyDLL可以安全地加载系统DLL。
type LazyDLL struct {
	LazyDLL父类 syscall.LazyDLL
}

// I创建_延迟加载 创建新LazyDLL。
func I创建_延迟加载(dll名称 string) *LazyDLL {
	返回 := syscall.NewLazyDLL(dll名称)
	if 返回 == nil {
		return nil
	}
	return &LazyDLL{*返回}
}

// I加载 将DLL文件d.名称加载到内存中。如果失败，则返回错误。
// 如果DLL已经加载到内存中，则不会尝试加载DLL。
func (d *LazyDLL) I加载() error {
	if d == nil {
		return errors.New("dll类对象为nil")
	}
	return d.LazyDLL父类.Load()
}

// I取模块地址 Handle 返回d的模块句柄。
func (d *LazyDLL) I取模块地址() uintptr {
	if d == nil {
		return 0
	}
	return d.LazyDLL父类.Handle()
}

// A LazyProc 实现对LazyDLL内部过程的访问。
// 它会延迟查找，直到调用Addr、Call或Find方法。
type LazyProc struct {
	LazyProc父类 syscall.LazyProc
}

// I创建命令对象 返回用于访问DLL d中的指定命令名。
func (d *LazyDLL) I创建命令对象(命令名 string) *LazyProc {
	返回 := d.LazyDLL父类.NewProc(命令名)
	if 返回 == nil {
		return nil
	}
	return &LazyProc{*返回}
}

// I查找命令 在DLL中搜索名为 "p.命令名" 的过程.
// 如果搜索失败，则返回错误。
// 如果已找到并加载到内存中，查找将不会搜索
func (p *LazyProc) I查找命令() error {
	// 非Racy版本：
	// if p.proc == nil {
	if p == nil {
		return errors.New("dll类对象为nil")
	}
	return p.LazyProc父类.Find()
}

// I取命令地址 Addr 返回dll内命令的地址。
// 返回值可以传递给 "I调用命令" 调用。
func (p *LazyProc) I取命令地址() uintptr {
	if p == nil {
		return 0
	}
	return p.LazyProc父类.Addr()
}

// I调用 使用参数a执行过程p。有关详细信息，请参阅Proc.Call的文档。
func (p *LazyProc) I调用(命令参数s ...uintptr) (r1, r2 uintptr, lastErr error) {
	if p == nil {
		return 0, 0, errors.New("dll类对象为nil")
	}
	return p.LazyProc父类.Call(命令参数s...)
}
