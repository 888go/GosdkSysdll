package dll类

//win封装好的api https://github.com/lxn/win
//win封装好的api https://github.com/iamacarpet/go-win64api
//win快捷方式 github.com/parsiya/golnk

import (
	"errors"
	"fmt"
	"github.com/gogf/gf/v2/container/gmap"
	"math"
	"reflect"
	"syscall"
	"unsafe"
)

type DLL快捷 struct {
	dll名称   string
	DLL对象   DLL
	已查找命令集合 gmap.StrAnyMap
}

type I执行结果 struct {
	R1    uintptr
	R2    uintptr
	Errno syscall.Errno
}

func I创建_快捷(dll名称 string) (*DLL快捷, error) {
	DLL, err := I创建(dll名称)
	gmap对象 := gmap.NewStrAnyMap(true)
	if DLL == nil {
		return nil, err
	}
	if gmap对象 == nil {
		return nil, errors.New("'map.New()' 调用返回nil")
	}
	return &DLL快捷{dll名称, *DLL, *gmap对象}, nil
}
func (d *DLL快捷) I调用(命令名 string, 参数 ...interface{}) (执行返回 I执行结果, err error) {
	if d.dll名称 == "" {
		return I执行结果{}, errors.New("dll应在初始化函数之前加载")
	}
	//查找命令地址
	var 命令地址 uintptr
	命令地址, _ = d.已查找命令集合.Get(命令名).(uintptr)
	if 命令地址 == 0 {
		查找命令, err := d.DLL对象.I查找命令(命令名)
		if err != nil {
			return I执行结果{}, errors.New(d.dll名称 + "->" + 命令名 + ",错误: dll命令不存在")
		} else {
			命令地址 = 查找命令.I取命令地址()
			d.已查找命令集合.Set(命令名, 命令地址)
		}
	}
	//开始运行
	var 新参数 []uintptr
	for _, 参数值 := range 参数 {
		var vPtr uintptr = 0
		switch v := 参数值.(type) {
		case string:
			vPtr = I文本到指针(v)
		case *string:
			//vPtr = uintptr(unsafe.Pointer(syscall.BytePtrFromString(*v)))
			//此方法处理的不一定正确,需要再求证
			ptxt, _ := syscall.BytePtrFromString(*v)
			vPtr = uintptr(unsafe.Pointer(ptxt))
		case bool:
			vPtr = BoolPtr(v)
		case int:
			vPtr = uintptr(v)
		case int8:
			vPtr = uintptr(v)
		case int16:
			vPtr = uintptr(v)
		case int32:
			vPtr = uintptr(v)
		case int64:
			vPtr = uintptr(v)
		case *int:
			vPtr = uintptr(unsafe.Pointer(v))
		case *int8:
			vPtr = uintptr(unsafe.Pointer(v))
		case *int16:
			vPtr = uintptr(unsafe.Pointer(v))
		case *int32:
			vPtr = uintptr(unsafe.Pointer(v))
		case *int64:
			vPtr = uintptr(unsafe.Pointer(v))
		case uint8:
			vPtr = uintptr(v)
		case uint16:
			vPtr = uintptr(v)
		case uint32:
			vPtr = uintptr(v)
		case uint64:
			vPtr = uintptr(v)
		case *uint8:
			vPtr = uintptr(unsafe.Pointer(v))
		case *uint16:
			vPtr = uintptr(unsafe.Pointer(v))
		case *uint32:
			vPtr = uintptr(unsafe.Pointer(v))
		case *uint64:
			vPtr = uintptr(unsafe.Pointer(v))
		case float32:
			vPtr = uintptr(math.Float32bits(v)) //方法来自gosdk,要传递C类型为“float”的参数x,使用uintptr(math.Float32bits(x)).
		case float64:
			vPtr = uintptr(math.Float64bits(v)) // 方法来自gosdk,传递C类型为“double”的参数，使用uintptr(math.Float64bits(x)).
		case []byte:
			vPtr = I字节集到指针(&v)
		case *[]byte:
			vPtr = I字节集到指针(v)
		case uintptr:
			vPtr = v
		case *uintptr:
			vPtr = uintptr(unsafe.Pointer(v)) //不确定有没这种值, 在https://github.com/lxn/win包看到的.
		default:
			类型反射 := reflect.TypeOf(v).Kind()
			if 类型反射 == reflect.Struct { //判断是否是结构
				vPtr = uintptr(unsafe.Pointer(&v))
			}
			//if 类型反射 == reflect.Ptr { //判断是否是结构引用指针
			//	测试, _ := v.(interface{})
			//	vPtr = uintptr(unsafe.Pointer(&测试))
			//}
			if 类型反射 != reflect.Struct {
				err = fmt.Errorf("不支持将类型%v转换为uintptr", reflect.TypeOf(参数值))
				return
			}
		}
		新参数 = append(新参数, vPtr)
	}
	执行返回.R1, 执行返回.R2, 执行返回.Errno = I调用命令(命令地址, 新参数...)
	return 执行返回, nil
}
func (d *DLL快捷) I卸载() error {
	d.dll名称 = ""
	d.已查找命令集合.Clear()
	return d.DLL对象.I卸载dll()
}
