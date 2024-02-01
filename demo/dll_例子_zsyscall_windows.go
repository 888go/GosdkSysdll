package demo

import (
	syscall "e.coding.net/gogit/go/gosdk/core/win_dll"
	"e.coding.net/gogit/go/gosdk/internal/syscall/windows/sysdll"
	syscall2 "syscall"
	"unsafe"
)

type SID struct{}
type Handle uintptr
type Token Handle

const InvalidHandle = ^Handle(0)
const socket_error = uintptr(^uint32(0))

var _ unsafe.Pointer
var SocketDisableIPv6 bool

type RawSockaddrInet4 struct {
	Family uint16
	Port   uint16
	Addr   [4]byte /* in_addr */
	Zero   [8]uint8
}

type RawSockaddrInet6 struct {
	Family   uint16
	Port     uint16
	Flowinfo uint32
	Addr     [16]byte /* in6_addr */
	Scope_id uint32
}

type RawSockaddr struct {
	Family uint16
	Data   [14]int8
}

type RawSockaddrAny struct {
	Addr RawSockaddr
	Pad  [100]int8
}

type Sockaddr interface {
	sockaddr() (ptr unsafe.Pointer, len int32, err error) // lowercase; only we can define Sockaddrs
}

type SockaddrInet4 struct {
	Port int
	Addr [4]byte
	raw  RawSockaddrInet4
}

// Do the interface allocations only once for common
// Errno values.
const (
	errnoERROR_IO_PENDING = 997
)

var (
	errERROR_IO_PENDING error = syscall2.Errno(errnoERROR_IO_PENDING)
	errERROR_EINVAL     error = syscall2.EINVAL
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall2.Errno) error {
	switch e {
	case 0:
		return errERROR_EINVAL
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	// TODO: 在收集公共数据后，在此处添加更多
	// 错误值请参阅Windows上的。（也许是在跑步时。蝙蝠？）
	return e
}

var (
	modadvapi32 = syscall.I创建_延迟加载(sysdll.Add("advapi32.dll"))
	modcrypt32  = syscall.I创建_延迟加载(sysdll.Add("crypt32.dll"))
	moddnsapi   = syscall.I创建_延迟加载(sysdll.Add("dnsapi.dll"))
	modiphlpapi = syscall.I创建_延迟加载(sysdll.Add("iphlpapi.dll"))
	modkernel32 = syscall.I创建_延迟加载(sysdll.Add("kernel32.dll"))
	modmswsock  = syscall.I创建_延迟加载(sysdll.Add("mswsock.dll"))
	modnetapi32 = syscall.I创建_延迟加载(sysdll.Add("netapi32.dll"))
	modntdll    = syscall.I创建_延迟加载(sysdll.Add("ntdll.dll"))
	modsecur32  = syscall.I创建_延迟加载(sysdll.Add("secur32.dll"))
	modshell32  = syscall.I创建_延迟加载(sysdll.Add("shell32.dll"))
	moduserenv  = syscall.I创建_延迟加载(sysdll.Add("userenv.dll"))
	modws2_32   = syscall.I创建_延迟加载(sysdll.Add("ws2_32.dll"))

	procConvertSidToStringSidW             = modadvapi32.I创建命令对象("ConvertSidToStringSidW")
	procConvertStringSidToSidW             = modadvapi32.I创建命令对象("ConvertStringSidToSidW")
	procCopySid                            = modadvapi32.I创建命令对象("CopySid")
	procCreateProcessAsUserW               = modadvapi32.I创建命令对象("CreateProcessAsUserW")
	procCryptAcquireContextW               = modadvapi32.I创建命令对象("CryptAcquireContextW")
	procCryptGenRandom                     = modadvapi32.I创建命令对象("CryptGenRandom")
	procCryptReleaseContext                = modadvapi32.I创建命令对象("CryptReleaseContext")
	procGetLengthSid                       = modadvapi32.I创建命令对象("GetLengthSid")
	procGetTokenInformation                = modadvapi32.I创建命令对象("GetTokenInformation")
	procLookupAccountNameW                 = modadvapi32.I创建命令对象("LookupAccountNameW")
	procLookupAccountSidW                  = modadvapi32.I创建命令对象("LookupAccountSidW")
	procOpenProcessToken                   = modadvapi32.I创建命令对象("OpenProcessToken")
	procRegCloseKey                        = modadvapi32.I创建命令对象("RegCloseKey")
	procRegEnumKeyExW                      = modadvapi32.I创建命令对象("RegEnumKeyExW")
	procRegOpenKeyExW                      = modadvapi32.I创建命令对象("RegOpenKeyExW")
	procRegQueryInfoKeyW                   = modadvapi32.I创建命令对象("RegQueryInfoKeyW")
	procRegQueryValueExW                   = modadvapi32.I创建命令对象("RegQueryValueExW")
	procCertAddCertificateContextToStore   = modcrypt32.I创建命令对象("CertAddCertificateContextToStore")
	procCertCloseStore                     = modcrypt32.I创建命令对象("CertCloseStore")
	procCertCreateCertificateContext       = modcrypt32.I创建命令对象("CertCreateCertificateContext")
	procCertEnumCertificatesInStore        = modcrypt32.I创建命令对象("CertEnumCertificatesInStore")
	procCertFreeCertificateChain           = modcrypt32.I创建命令对象("CertFreeCertificateChain")
	procCertFreeCertificateContext         = modcrypt32.I创建命令对象("CertFreeCertificateContext")
	procCertGetCertificateChain            = modcrypt32.I创建命令对象("CertGetCertificateChain")
	procCertOpenStore                      = modcrypt32.I创建命令对象("CertOpenStore")
	procCertOpenSystemStoreW               = modcrypt32.I创建命令对象("CertOpenSystemStoreW")
	procCertVerifyCertificateChainPolicy   = modcrypt32.I创建命令对象("CertVerifyCertificateChainPolicy")
	procDnsNameCompare_W                   = moddnsapi.I创建命令对象("DnsNameCompare_W")
	procDnsQuery_W                         = moddnsapi.I创建命令对象("DnsQuery_W")
	procDnsRecordListFree                  = moddnsapi.I创建命令对象("DnsRecordListFree")
	procGetAdaptersInfo                    = modiphlpapi.I创建命令对象("GetAdaptersInfo")
	procGetIfEntry                         = modiphlpapi.I创建命令对象("GetIfEntry")
	procCancelIo                           = modkernel32.I创建命令对象("CancelIo")
	procCancelIoEx                         = modkernel32.I创建命令对象("CancelIoEx")
	procCloseHandle                        = modkernel32.I创建命令对象("CloseHandle")
	procCreateDirectoryW                   = modkernel32.I创建命令对象("CreateDirectoryW")
	procCreateFileMappingW                 = modkernel32.I创建命令对象("CreateFileMappingW")
	procCreateFileW                        = modkernel32.I创建命令对象("CreateFileW")
	procCreateHardLinkW                    = modkernel32.I创建命令对象("CreateHardLinkW")
	procCreateIoCompletionPort             = modkernel32.I创建命令对象("CreateIoCompletionPort")
	procCreatePipe                         = modkernel32.I创建命令对象("CreatePipe")
	procCreateProcessW                     = modkernel32.I创建命令对象("CreateProcessW")
	procCreateSymbolicLinkW                = modkernel32.I创建命令对象("CreateSymbolicLinkW")
	procCreateToolhelp32Snapshot           = modkernel32.I创建命令对象("CreateToolhelp32Snapshot")
	procDeleteFileW                        = modkernel32.I创建命令对象("DeleteFileW")
	procDeleteProcThreadAttributeList      = modkernel32.I创建命令对象("DeleteProcThreadAttributeList")
	procDeviceIoControl                    = modkernel32.I创建命令对象("DeviceIoControl")
	procDuplicateHandle                    = modkernel32.I创建命令对象("DuplicateHandle")
	procExitProcess                        = modkernel32.I创建命令对象("ExitProcess")
	procFindClose                          = modkernel32.I创建命令对象("FindClose")
	procFindFirstFileW                     = modkernel32.I创建命令对象("FindFirstFileW")
	procFindNextFileW                      = modkernel32.I创建命令对象("FindNextFileW")
	procFlushFileBuffers                   = modkernel32.I创建命令对象("FlushFileBuffers")
	procFlushViewOfFile                    = modkernel32.I创建命令对象("FlushViewOfFile")
	procFormatMessageW                     = modkernel32.I创建命令对象("FormatMessageW")
	procFreeEnvironmentStringsW            = modkernel32.I创建命令对象("FreeEnvironmentStringsW")
	procFreeLibrary                        = modkernel32.I创建命令对象("FreeLibrary")
	procGetCommandLineW                    = modkernel32.I创建命令对象("GetCommandLineW")
	procGetComputerNameW                   = modkernel32.I创建命令对象("GetComputerNameW")
	procGetConsoleMode                     = modkernel32.I创建命令对象("GetConsoleMode")
	procGetCurrentDirectoryW               = modkernel32.I创建命令对象("GetCurrentDirectoryW")
	procGetCurrentProcess                  = modkernel32.I创建命令对象("GetCurrentProcess")
	procGetCurrentProcessId                = modkernel32.I创建命令对象("GetCurrentProcessId")
	procGetEnvironmentStringsW             = modkernel32.I创建命令对象("GetEnvironmentStringsW")
	procGetEnvironmentVariableW            = modkernel32.I创建命令对象("GetEnvironmentVariableW")
	procGetExitCodeProcess                 = modkernel32.I创建命令对象("GetExitCodeProcess")
	procGetFileAttributesExW               = modkernel32.I创建命令对象("GetFileAttributesExW")
	procGetFileAttributesW                 = modkernel32.I创建命令对象("GetFileAttributesW")
	procGetFileInformationByHandle         = modkernel32.I创建命令对象("GetFileInformationByHandle")
	procGetFileType                        = modkernel32.I创建命令对象("GetFileType")
	procGetFullPathNameW                   = modkernel32.I创建命令对象("GetFullPathNameW")
	procGetLastError                       = modkernel32.I创建命令对象("GetLastError")
	procGetLongPathNameW                   = modkernel32.I创建命令对象("GetLongPathNameW")
	procGetProcAddress                     = modkernel32.I创建命令对象("GetProcAddress")
	procGetProcessTimes                    = modkernel32.I创建命令对象("GetProcessTimes")
	procGetQueuedCompletionStatus          = modkernel32.I创建命令对象("GetQueuedCompletionStatus")
	procGetShortPathNameW                  = modkernel32.I创建命令对象("GetShortPathNameW")
	procGetStartupInfoW                    = modkernel32.I创建命令对象("GetStartupInfoW")
	procGetStdHandle                       = modkernel32.I创建命令对象("GetStdHandle")
	procGetSystemDirectoryW                = modkernel32.I创建命令对象("GetSystemDirectoryW")
	procGetSystemTimeAsFileTime            = modkernel32.I创建命令对象("GetSystemTimeAsFileTime")
	procGetTempPathW                       = modkernel32.I创建命令对象("GetTempPathW")
	procGetTimeZoneInformation             = modkernel32.I创建命令对象("GetTimeZoneInformation")
	procGetVersion                         = modkernel32.I创建命令对象("GetVersion")
	procInitializeProcThreadAttributeList  = modkernel32.I创建命令对象("InitializeProcThreadAttributeList")
	procLoadLibraryW                       = modkernel32.I创建命令对象("LoadLibraryW")
	procLocalFree                          = modkernel32.I创建命令对象("LocalFree")
	procMapViewOfFile                      = modkernel32.I创建命令对象("MapViewOfFile")
	procMoveFileW                          = modkernel32.I创建命令对象("MoveFileW")
	procOpenProcess                        = modkernel32.I创建命令对象("OpenProcess")
	procPostQueuedCompletionStatus         = modkernel32.I创建命令对象("PostQueuedCompletionStatus")
	procProcess32FirstW                    = modkernel32.I创建命令对象("Process32FirstW")
	procProcess32NextW                     = modkernel32.I创建命令对象("Process32NextW")
	procReadConsoleW                       = modkernel32.I创建命令对象("ReadConsoleW")
	procReadDirectoryChangesW              = modkernel32.I创建命令对象("ReadDirectoryChangesW")
	procReadFile                           = modkernel32.I创建命令对象("ReadFile")
	procRemoveDirectoryW                   = modkernel32.I创建命令对象("RemoveDirectoryW")
	procSetCurrentDirectoryW               = modkernel32.I创建命令对象("SetCurrentDirectoryW")
	procSetEndOfFile                       = modkernel32.I创建命令对象("SetEndOfFile")
	procSetEnvironmentVariableW            = modkernel32.I创建命令对象("SetEnvironmentVariableW")
	procSetFileAttributesW                 = modkernel32.I创建命令对象("SetFileAttributesW")
	procSetFileCompletionNotificationModes = modkernel32.I创建命令对象("SetFileCompletionNotificationModes")
	procSetFilePointer                     = modkernel32.I创建命令对象("SetFilePointer")
	procSetFileTime                        = modkernel32.I创建命令对象("SetFileTime")
	procSetHandleInformation               = modkernel32.I创建命令对象("SetHandleInformation")
	procTerminateProcess                   = modkernel32.I创建命令对象("TerminateProcess")
	procUnmapViewOfFile                    = modkernel32.I创建命令对象("UnmapViewOfFile")
	procUpdateProcThreadAttribute          = modkernel32.I创建命令对象("UpdateProcThreadAttribute")
	procVirtualLock                        = modkernel32.I创建命令对象("VirtualLock")
	procVirtualUnlock                      = modkernel32.I创建命令对象("VirtualUnlock")
	procWaitForSingleObject                = modkernel32.I创建命令对象("WaitForSingleObject")
	procWriteConsoleW                      = modkernel32.I创建命令对象("WriteConsoleW")
	procWriteFile                          = modkernel32.I创建命令对象("WriteFile")
	procAcceptEx                           = modmswsock.I创建命令对象("AcceptEx")
	procGetAcceptExSockaddrs               = modmswsock.I创建命令对象("GetAcceptExSockaddrs")
	procTransmitFile                       = modmswsock.I创建命令对象("TransmitFile")
	procNetApiBufferFree                   = modnetapi32.I创建命令对象("NetApiBufferFree")
	procNetGetJoinInformation              = modnetapi32.I创建命令对象("NetGetJoinInformation")
	procNetUserGetInfo                     = modnetapi32.I创建命令对象("NetUserGetInfo")
	procRtlGetNtVersionNumbers             = modntdll.I创建命令对象("RtlGetNtVersionNumbers")
	procGetUserNameExW                     = modsecur32.I创建命令对象("GetUserNameExW")
	procTranslateNameW                     = modsecur32.I创建命令对象("TranslateNameW")
	procCommandLineToArgvW                 = modshell32.I创建命令对象("CommandLineToArgvW")
	procGetUserProfileDirectoryW           = moduserenv.I创建命令对象("GetUserProfileDirectoryW")
	procFreeAddrInfoW                      = modws2_32.I创建命令对象("FreeAddrInfoW")
	procGetAddrInfoW                       = modws2_32.I创建命令对象("GetAddrInfoW")
	procWSACleanup                         = modws2_32.I创建命令对象("WSACleanup")
	procWSAEnumProtocolsW                  = modws2_32.I创建命令对象("WSAEnumProtocolsW")
	procWSAIoctl                           = modws2_32.I创建命令对象("WSAIoctl")
	procWSARecv                            = modws2_32.I创建命令对象("WSARecv")
	procWSARecvFrom                        = modws2_32.I创建命令对象("WSARecvFrom")
	procWSASend                            = modws2_32.I创建命令对象("WSASend")
	procWSASendTo                          = modws2_32.I创建命令对象("WSASendTo")
	procWSAStartup                         = modws2_32.I创建命令对象("WSAStartup")
	procbind                               = modws2_32.I创建命令对象("bind")
	procclosesocket                        = modws2_32.I创建命令对象("closesocket")
	procconnect                            = modws2_32.I创建命令对象("connect")
	procgethostbyname                      = modws2_32.I创建命令对象("gethostbyname")
	procgetpeername                        = modws2_32.I创建命令对象("getpeername")
	procgetprotobyname                     = modws2_32.I创建命令对象("getprotobyname")
	procgetservbyname                      = modws2_32.I创建命令对象("getservbyname")
	procgetsockname                        = modws2_32.I创建命令对象("getsockname")
	procgetsockopt                         = modws2_32.I创建命令对象("getsockopt")
	proclisten                             = modws2_32.I创建命令对象("listen")
	procntohs                              = modws2_32.I创建命令对象("ntohs")
	procsetsockopt                         = modws2_32.I创建命令对象("setsockopt")
	procshutdown                           = modws2_32.I创建命令对象("shutdown")
	procsocket                             = modws2_32.I创建命令对象("socket")
)

func ConvertSidToStringSid(sid *SID, stringSid **uint16) (err error) {
	r1, _, e1 := syscall.I调用命令3(procConvertSidToStringSidW.I取命令地址(), 2, uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(stringSid)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func ConvertStringSidToSid(stringSid *uint16, sid **SID) (err error) {
	r1, _, e1 := syscall.I调用命令3(procConvertStringSidToSidW.I取命令地址(), 2, uintptr(unsafe.Pointer(stringSid)), uintptr(unsafe.Pointer(sid)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func CopySid(destSidLen uint32, destSid *SID, srcSid *SID) (err error) {
	r1, _, e1 := syscall.I调用命令3(procCopySid.I取命令地址(), 3, uintptr(destSidLen), uintptr(unsafe.Pointer(destSid)), uintptr(unsafe.Pointer(srcSid)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func CreateProcessAsUser(token Token, appName *uint16, commandLine *uint16, procSecurity *SecurityAttributes, threadSecurity *SecurityAttributes, inheritHandles bool, creationFlags uint32, env *uint16, currentDir *uint16, startupInfo *StartupInfo, outProcInfo *ProcessInformation) (err error) {
	var _p0 uint32
	if inheritHandles {
		_p0 = 1
	}
	r1, _, e1 := syscall.I调用命令12(procCreateProcessAsUserW.I取命令地址(), 11, uintptr(token), uintptr(unsafe.Pointer(appName)), uintptr(unsafe.Pointer(commandLine)), uintptr(unsafe.Pointer(procSecurity)), uintptr(unsafe.Pointer(threadSecurity)), uintptr(_p0), uintptr(creationFlags), uintptr(unsafe.Pointer(env)), uintptr(unsafe.Pointer(currentDir)), uintptr(unsafe.Pointer(startupInfo)), uintptr(unsafe.Pointer(outProcInfo)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func CryptAcquireContext(provhandle *uintptr, container *uint16, provider *uint16, provtype uint32, flags uint32) (err error) {
	r1, _, e1 := syscall.I调用命令6(procCryptAcquireContextW.I取命令地址(), 5, uintptr(unsafe.Pointer(provhandle)), uintptr(unsafe.Pointer(container)), uintptr(unsafe.Pointer(provider)), uintptr(provtype), uintptr(flags), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func CryptGenRandom(provhandle uintptr, buflen uint32, buf *byte) (err error) {
	r1, _, e1 := syscall.I调用命令3(procCryptGenRandom.I取命令地址(), 3, uintptr(provhandle), uintptr(buflen), uintptr(unsafe.Pointer(buf)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func CryptReleaseContext(provhandle uintptr, flags uint32) (err error) {
	r1, _, e1 := syscall.I调用命令3(procCryptReleaseContext.I取命令地址(), 2, uintptr(provhandle), uintptr(flags), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetLengthSid(sid *SID) (len uint32) {
	r0, _, _ := syscall.I调用命令3(procGetLengthSid.I取命令地址(), 1, uintptr(unsafe.Pointer(sid)), 0, 0)
	len = uint32(r0)
	return
}

func GetTokenInformation(t Token, infoClass uint32, info *byte, infoLen uint32, returnedLen *uint32) (err error) {
	r1, _, e1 := syscall.I调用命令6(procGetTokenInformation.I取命令地址(), 5, uintptr(t), uintptr(infoClass), uintptr(unsafe.Pointer(info)), uintptr(infoLen), uintptr(unsafe.Pointer(returnedLen)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func LookupAccountName(systemName *uint16, accountName *uint16, sid *SID, sidLen *uint32, refdDomainName *uint16, refdDomainNameLen *uint32, use *uint32) (err error) {
	r1, _, e1 := syscall.I调用命令9(procLookupAccountNameW.I取命令地址(), 7, uintptr(unsafe.Pointer(systemName)), uintptr(unsafe.Pointer(accountName)), uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(sidLen)), uintptr(unsafe.Pointer(refdDomainName)), uintptr(unsafe.Pointer(refdDomainNameLen)), uintptr(unsafe.Pointer(use)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func LookupAccountSid(systemName *uint16, sid *SID, name *uint16, nameLen *uint32, refdDomainName *uint16, refdDomainNameLen *uint32, use *uint32) (err error) {
	r1, _, e1 := syscall.I调用命令9(procLookupAccountSidW.I取命令地址(), 7, uintptr(unsafe.Pointer(systemName)), uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(nameLen)), uintptr(unsafe.Pointer(refdDomainName)), uintptr(unsafe.Pointer(refdDomainNameLen)), uintptr(unsafe.Pointer(use)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func OpenProcessToken(h uintptr, access uint32, token *Token) (err error) {
	r1, _, e1 := syscall.I调用命令3(procOpenProcessToken.I取命令地址(), 3, uintptr(h), uintptr(access), uintptr(unsafe.Pointer(token)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func RegCloseKey(key uintptr) (regerrno error) {
	r0, _, _ := syscall.I调用命令3(procRegCloseKey.I取命令地址(), 1, uintptr(key), 0, 0)
	if r0 != 0 {
		regerrno = syscall2.Errno(r0)
	}
	return
}

func regEnumKeyEx(key uintptr, index uint32, name *uint16, nameLen *uint32, reserved *uint32, class *uint16, classLen *uint32, lastWriteTime *Filetime) (regerrno error) {
	r0, _, _ := syscall.I调用命令9(procRegEnumKeyExW.I取命令地址(), 8, uintptr(key), uintptr(index), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(nameLen)), uintptr(unsafe.Pointer(reserved)), uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(classLen)), uintptr(unsafe.Pointer(lastWriteTime)), 0)
	if r0 != 0 {
		regerrno = syscall2.Errno(r0)
	}
	return
}

func RegOpenKeyEx(key uintptr, subkey *uint16, options uint32, desiredAccess uint32, result *uintptr) (regerrno error) {
	r0, _, _ := syscall.I调用命令6(procRegOpenKeyExW.I取命令地址(), 5, uintptr(key), uintptr(unsafe.Pointer(subkey)), uintptr(options), uintptr(desiredAccess), uintptr(unsafe.Pointer(result)), 0)
	if r0 != 0 {
		regerrno = syscall2.Errno(r0)
	}
	return
}

func RegQueryInfoKey(key uintptr, class *uint16, classLen *uint32, reserved *uint32, subkeysLen *uint32, maxSubkeyLen *uint32, maxClassLen *uint32, valuesLen *uint32, maxValueNameLen *uint32, maxValueLen *uint32, saLen *uint32, lastWriteTime *Filetime) (regerrno error) {
	r0, _, _ := syscall.I调用命令12(procRegQueryInfoKeyW.I取命令地址(), 12, uintptr(key), uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(classLen)), uintptr(unsafe.Pointer(reserved)), uintptr(unsafe.Pointer(subkeysLen)), uintptr(unsafe.Pointer(maxSubkeyLen)), uintptr(unsafe.Pointer(maxClassLen)), uintptr(unsafe.Pointer(valuesLen)), uintptr(unsafe.Pointer(maxValueNameLen)), uintptr(unsafe.Pointer(maxValueLen)), uintptr(unsafe.Pointer(saLen)), uintptr(unsafe.Pointer(lastWriteTime)))
	if r0 != 0 {
		regerrno = syscall2.Errno(r0)
	}
	return
}

func RegQueryValueEx(key uintptr, name *uint16, reserved *uint32, valtype *uint32, buf *byte, buflen *uint32) (regerrno error) {
	r0, _, _ := syscall.I调用命令6(procRegQueryValueExW.I取命令地址(), 6, uintptr(key), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(reserved)), uintptr(unsafe.Pointer(valtype)), uintptr(unsafe.Pointer(buf)), uintptr(unsafe.Pointer(buflen)))
	if r0 != 0 {
		regerrno = syscall2.Errno(r0)
	}
	return
}

func CertAddCertificateContextToStore(store uintptr, certContext *CertContext, addDisposition uint32, storeContext **CertContext) (err error) {
	r1, _, e1 := syscall.I调用命令6(procCertAddCertificateContextToStore.I取命令地址(), 4, uintptr(store), uintptr(unsafe.Pointer(certContext)), uintptr(addDisposition), uintptr(unsafe.Pointer(storeContext)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func CertCloseStore(store uintptr, flags uint32) (err error) {
	r1, _, e1 := syscall.I调用命令3(procCertCloseStore.I取命令地址(), 2, uintptr(store), uintptr(flags), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func CertCreateCertificateContext(certEncodingType uint32, certEncoded *byte, encodedLen uint32) (context *CertContext, err error) {
	r0, _, e1 := syscall.I调用命令3(procCertCreateCertificateContext.I取命令地址(), 3, uintptr(certEncodingType), uintptr(unsafe.Pointer(certEncoded)), uintptr(encodedLen))
	context = (*CertContext)(unsafe.Pointer(r0))
	if context == nil {
		err = errnoErr(e1)
	}
	return
}

func CertEnumCertificatesInStore(store uintptr, prevContext *CertContext) (context *CertContext, err error) {
	r0, _, e1 := syscall.I调用命令3(procCertEnumCertificatesInStore.I取命令地址(), 2, uintptr(store), uintptr(unsafe.Pointer(prevContext)), 0)
	context = (*CertContext)(unsafe.Pointer(r0))
	if context == nil {
		err = errnoErr(e1)
	}
	return
}

func CertFreeCertificateChain(ctx *CertChainContext) {
	syscall.I调用命令3(procCertFreeCertificateChain.I取命令地址(), 1, uintptr(unsafe.Pointer(ctx)), 0, 0)
	return
}

func CertFreeCertificateContext(ctx *CertContext) (err error) {
	r1, _, e1 := syscall.I调用命令3(procCertFreeCertificateContext.I取命令地址(), 1, uintptr(unsafe.Pointer(ctx)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func CertGetCertificateChain(engine uintptr, leaf *CertContext, time *Filetime, additionalStore uintptr, para *CertChainPara, flags uint32, reserved uintptr, chainCtx **CertChainContext) (err error) {
	r1, _, e1 := syscall.I调用命令9(procCertGetCertificateChain.I取命令地址(), 8, uintptr(engine), uintptr(unsafe.Pointer(leaf)), uintptr(unsafe.Pointer(time)), uintptr(additionalStore), uintptr(unsafe.Pointer(para)), uintptr(flags), uintptr(reserved), uintptr(unsafe.Pointer(chainCtx)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func CertOpenStore(storeProvider uintptr, msgAndCertEncodingType uint32, cryptProv uintptr, flags uint32, para uintptr) (handle uintptr, err error) {
	r0, _, e1 := syscall.I调用命令6(procCertOpenStore.I取命令地址(), 5, uintptr(storeProvider), uintptr(msgAndCertEncodingType), uintptr(cryptProv), uintptr(flags), uintptr(para), 0)
	handle = uintptr(r0)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

func CertOpenSystemStore(hprov uintptr, name *uint16) (store uintptr, err error) {
	r0, _, e1 := syscall.I调用命令3(procCertOpenSystemStoreW.I取命令地址(), 2, uintptr(hprov), uintptr(unsafe.Pointer(name)), 0)
	store = uintptr(r0)
	if store == 0 {
		err = errnoErr(e1)
	}
	return
}

func CertVerifyCertificateChainPolicy(policyOID uintptr, chain *CertChainContext, para *CertChainPolicyPara, status *CertChainPolicyStatus) (err error) {
	r1, _, e1 := syscall.I调用命令6(procCertVerifyCertificateChainPolicy.I取命令地址(), 4, uintptr(policyOID), uintptr(unsafe.Pointer(chain)), uintptr(unsafe.Pointer(para)), uintptr(unsafe.Pointer(status)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func DnsNameCompare(name1 *uint16, name2 *uint16) (same bool) {
	r0, _, _ := syscall.I调用命令3(procDnsNameCompare_W.I取命令地址(), 2, uintptr(unsafe.Pointer(name1)), uintptr(unsafe.Pointer(name2)), 0)
	same = r0 != 0
	return
}

func DnsQuery(name string, qtype uint16, options uint32, extra *byte, qrs **DNSRecord, pr *byte) (status error) {
	var _p0 *uint16
	_p0, status = syscall.UTF16PtrFromString(name)
	if status != nil {
		return
	}
	return _DnsQuery(_p0, qtype, options, extra, qrs, pr)
}

func _DnsQuery(name *uint16, qtype uint16, options uint32, extra *byte, qrs **DNSRecord, pr *byte) (status error) {
	r0, _, _ := syscall.I调用命令6(procDnsQuery_W.I取命令地址(), 6, uintptr(unsafe.Pointer(name)), uintptr(qtype), uintptr(options), uintptr(unsafe.Pointer(extra)), uintptr(unsafe.Pointer(qrs)), uintptr(unsafe.Pointer(pr)))
	if r0 != 0 {
		status = syscall2.Errno(r0)
	}
	return
}

func DnsRecordListFree(rl *DNSRecord, freetype uint32) {
	syscall.I调用命令3(procDnsRecordListFree.I取命令地址(), 2, uintptr(unsafe.Pointer(rl)), uintptr(freetype), 0)
	return
}

func GetAdaptersInfo(ai *IpAdapterInfo, ol *uint32) (errcode error) {
	r0, _, _ := syscall.I调用命令3(procGetAdaptersInfo.I取命令地址(), 2, uintptr(unsafe.Pointer(ai)), uintptr(unsafe.Pointer(ol)), 0)
	if r0 != 0 {
		errcode = syscall2.Errno(r0)
	}
	return
}

func GetIfEntry(pIfRow *MibIfRow) (errcode error) {
	r0, _, _ := syscall.I调用命令3(procGetIfEntry.I取命令地址(), 1, uintptr(unsafe.Pointer(pIfRow)), 0, 0)
	if r0 != 0 {
		errcode = syscall2.Errno(r0)
	}
	return
}

func CancelIo(s uintptr) (err error) {
	r1, _, e1 := syscall.I调用命令3(procCancelIo.I取命令地址(), 1, uintptr(s), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func CancelIoEx(s uintptr, o *Overlapped) (err error) {
	r1, _, e1 := syscall.I调用命令3(procCancelIoEx.I取命令地址(), 2, uintptr(s), uintptr(unsafe.Pointer(o)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func CloseHandle(handle uintptr) (err error) {
	r1, _, e1 := syscall.I调用命令3(procCloseHandle.I取命令地址(), 1, uintptr(handle), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func CreateDirectory(path *uint16, sa *SecurityAttributes) (err error) {
	r1, _, e1 := syscall.I调用命令3(procCreateDirectoryW.I取命令地址(), 2, uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(sa)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func CreateFileMapping(fhandle uintptr, sa *SecurityAttributes, prot uint32, maxSizeHigh uint32, maxSizeLow uint32, name *uint16) (handle uintptr, err error) {
	r0, _, e1 := syscall.I调用命令6(procCreateFileMappingW.I取命令地址(), 6, uintptr(fhandle), uintptr(unsafe.Pointer(sa)), uintptr(prot), uintptr(maxSizeHigh), uintptr(maxSizeLow), uintptr(unsafe.Pointer(name)))
	handle = uintptr(r0)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

func CreateHardLink(filename *uint16, existingfilename *uint16, reserved uintptr) (err error) {
	r1, _, e1 := syscall.I调用命令3(procCreateHardLinkW.I取命令地址(), 3, uintptr(unsafe.Pointer(filename)), uintptr(unsafe.Pointer(existingfilename)), uintptr(reserved))
	if r1&0xff == 0 {
		err = errnoErr(e1)
	}
	return
}

func createIoCompletionPort(filehandle uintptr, cphandle uintptr, key uintptr, threadcnt uint32) (handle uintptr, err error) {
	r0, _, e1 := syscall.I调用命令6(procCreateIoCompletionPort.I取命令地址(), 4, uintptr(filehandle), uintptr(cphandle), uintptr(key), uintptr(threadcnt), 0, 0)
	handle = uintptr(r0)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

func CreatePipe(readhandle *uintptr, writehandle *uintptr, sa *SecurityAttributes, size uint32) (err error) {
	r1, _, e1 := syscall.I调用命令6(procCreatePipe.I取命令地址(), 4, uintptr(unsafe.Pointer(readhandle)), uintptr(unsafe.Pointer(writehandle)), uintptr(unsafe.Pointer(sa)), uintptr(size), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func CreateProcess(appName *uint16, commandLine *uint16, procSecurity *SecurityAttributes, threadSecurity *SecurityAttributes, inheritHandles bool, creationFlags uint32, env *uint16, currentDir *uint16, startupInfo *StartupInfo, outProcInfo *ProcessInformation) (err error) {
	var _p0 uint32
	if inheritHandles {
		_p0 = 1
	}
	r1, _, e1 := syscall.I调用命令12(procCreateProcessW.I取命令地址(), 10, uintptr(unsafe.Pointer(appName)), uintptr(unsafe.Pointer(commandLine)), uintptr(unsafe.Pointer(procSecurity)), uintptr(unsafe.Pointer(threadSecurity)), uintptr(_p0), uintptr(creationFlags), uintptr(unsafe.Pointer(env)), uintptr(unsafe.Pointer(currentDir)), uintptr(unsafe.Pointer(startupInfo)), uintptr(unsafe.Pointer(outProcInfo)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func CreateSymbolicLink(symlinkfilename *uint16, targetfilename *uint16, flags uint32) (err error) {
	r1, _, e1 := syscall.I调用命令3(procCreateSymbolicLinkW.I取命令地址(), 3, uintptr(unsafe.Pointer(symlinkfilename)), uintptr(unsafe.Pointer(targetfilename)), uintptr(flags))
	if r1&0xff == 0 {
		err = errnoErr(e1)
	}
	return
}

func DeleteFile(path *uint16) (err error) {
	r1, _, e1 := syscall.I调用命令3(procDeleteFileW.I取命令地址(), 1, uintptr(unsafe.Pointer(path)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func deleteProcThreadAttributeList(attrlist *_PROC_THREAD_ATTRIBUTE_LIST) {
	syscall.I调用命令3(procDeleteProcThreadAttributeList.I取命令地址(), 1, uintptr(unsafe.Pointer(attrlist)), 0, 0)
	return
}

func DeviceIoControl(handle uintptr, ioControlCode uint32, inBuffer *byte, inBufferSize uint32, outBuffer *byte, outBufferSize uint32, bytesReturned *uint32, overlapped *Overlapped) (err error) {
	r1, _, e1 := syscall.I调用命令9(procDeviceIoControl.I取命令地址(), 8, uintptr(handle), uintptr(ioControlCode), uintptr(unsafe.Pointer(inBuffer)), uintptr(inBufferSize), uintptr(unsafe.Pointer(outBuffer)), uintptr(outBufferSize), uintptr(unsafe.Pointer(bytesReturned)), uintptr(unsafe.Pointer(overlapped)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func DuplicateHandle(hSourceProcessHandle uintptr, hSourceHandle uintptr, hTargetProcessHandle uintptr, lpTargetHandle *uintptr, dwDesiredAccess uint32, bInheritHandle bool, dwOptions uint32) (err error) {
	var _p0 uint32
	if bInheritHandle {
		_p0 = 1
	}
	r1, _, e1 := syscall.I调用命令9(procDuplicateHandle.I取命令地址(), 7, uintptr(hSourceProcessHandle), uintptr(hSourceHandle), uintptr(hTargetProcessHandle), uintptr(unsafe.Pointer(lpTargetHandle)), uintptr(dwDesiredAccess), uintptr(_p0), uintptr(dwOptions), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func ExitProcess(exitcode uint32) {
	syscall.I调用命令3(procExitProcess.I取命令地址(), 1, uintptr(exitcode), 0, 0)
	return
}

func FindClose(handle uintptr) (err error) {
	r1, _, e1 := syscall.I调用命令3(procFindClose.I取命令地址(), 1, uintptr(handle), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func findNextFile1(handle uintptr, data *win32finddata1) (err error) {
	r1, _, e1 := syscall.I调用命令3(procFindNextFileW.I取命令地址(), 2, uintptr(handle), uintptr(unsafe.Pointer(data)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func FlushFileBuffers(handle uintptr) (err error) {
	r1, _, e1 := syscall.I调用命令3(procFlushFileBuffers.I取命令地址(), 1, uintptr(handle), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func FlushViewOfFile(addr uintptr, length uintptr) (err error) {
	r1, _, e1 := syscall.I调用命令3(procFlushViewOfFile.I取命令地址(), 2, uintptr(addr), uintptr(length), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func formatMessage(flags uint32, msgsrc uintptr, msgid uint32, langid uint32, buf []uint16, args *byte) (n uint32, err error) {
	var _p0 *uint16
	if len(buf) > 0 {
		_p0 = &buf[0]
	}
	r0, _, e1 := syscall.I调用命令9(procFormatMessageW.I取命令地址(), 7, uintptr(flags), uintptr(msgsrc), uintptr(msgid), uintptr(langid), uintptr(unsafe.Pointer(_p0)), uintptr(len(buf)), uintptr(unsafe.Pointer(args)), 0, 0)
	n = uint32(r0)
	if n == 0 {
		err = errnoErr(e1)
	}
	return
}

func FreeEnvironmentStrings(envs *uint16) (err error) {
	r1, _, e1 := syscall.I调用命令3(procFreeEnvironmentStringsW.I取命令地址(), 1, uintptr(unsafe.Pointer(envs)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func FreeLibrary(handle uintptr) (err error) {
	r1, _, e1 := syscall.I调用命令3(procFreeLibrary.I取命令地址(), 1, uintptr(handle), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetCommandLine() (cmd *uint16) {
	r0, _, _ := syscall.I调用命令3(procGetCommandLineW.I取命令地址(), 0, 0, 0, 0)
	cmd = (*uint16)(unsafe.Pointer(r0))
	return
}

func GetComputerName(buf *uint16, n *uint32) (err error) {
	r1, _, e1 := syscall.I调用命令3(procGetComputerNameW.I取命令地址(), 2, uintptr(unsafe.Pointer(buf)), uintptr(unsafe.Pointer(n)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetConsoleMode(console uintptr, mode *uint32) (err error) {
	r1, _, e1 := syscall.I调用命令3(procGetConsoleMode.I取命令地址(), 2, uintptr(console), uintptr(unsafe.Pointer(mode)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetCurrentDirectory(buflen uint32, buf *uint16) (n uint32, err error) {
	r0, _, e1 := syscall.I调用命令3(procGetCurrentDirectoryW.I取命令地址(), 2, uintptr(buflen), uintptr(unsafe.Pointer(buf)), 0)
	n = uint32(r0)
	if n == 0 {
		err = errnoErr(e1)
	}
	return
}

func getCurrentProcessId() (pid uint32) {
	r0, _, _ := syscall.I调用命令3(procGetCurrentProcessId.I取命令地址(), 0, 0, 0, 0)
	pid = uint32(r0)
	return
}

func GetEnvironmentStrings() (envs *uint16, err error) {
	r0, _, e1 := syscall.I调用命令3(procGetEnvironmentStringsW.I取命令地址(), 0, 0, 0, 0)
	envs = (*uint16)(unsafe.Pointer(r0))
	if envs == nil {
		err = errnoErr(e1)
	}
	return
}

func GetEnvironmentVariable(name *uint16, buffer *uint16, size uint32) (n uint32, err error) {
	r0, _, e1 := syscall.I调用命令3(procGetEnvironmentVariableW.I取命令地址(), 3, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(buffer)), uintptr(size))
	n = uint32(r0)
	if n == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetExitCodeProcess(handle Handle, exitcode *uint32) (err error) {
	r1, _, e1 := syscall.I调用命令3(procGetExitCodeProcess.I取命令地址(), 2, uintptr(handle), uintptr(unsafe.Pointer(exitcode)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetFileAttributesEx(name *uint16, level uint32, info *byte) (err error) {
	r1, _, e1 := syscall.I调用命令3(procGetFileAttributesExW.I取命令地址(), 3, uintptr(unsafe.Pointer(name)), uintptr(level), uintptr(unsafe.Pointer(info)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetFileAttributes(name *uint16) (attrs uint32, err error) {
	r0, _, e1 := syscall.I调用命令3(procGetFileAttributesW.I取命令地址(), 1, uintptr(unsafe.Pointer(name)), 0, 0)
	attrs = uint32(r0)
	if attrs == INVALID_FILE_ATTRIBUTES {
		err = errnoErr(e1)
	}
	return
}

func GetFileInformationByHandle(handle Handle, data *ByHandleFileInformation) (err error) {
	r1, _, e1 := syscall.I调用命令3(procGetFileInformationByHandle.I取命令地址(), 2, uintptr(handle), uintptr(unsafe.Pointer(data)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetFileType(filehandle Handle) (n uint32, err error) {
	r0, _, e1 := syscall.I调用命令3(procGetFileType.I取命令地址(), 1, uintptr(filehandle), 0, 0)
	n = uint32(r0)
	if n == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetFullPathName(path *uint16, buflen uint32, buf *uint16, fname **uint16) (n uint32, err error) {
	r0, _, e1 := syscall.I调用命令6(procGetFullPathNameW.I取命令地址(), 4, uintptr(unsafe.Pointer(path)), uintptr(buflen), uintptr(unsafe.Pointer(buf)), uintptr(unsafe.Pointer(fname)), 0, 0)
	n = uint32(r0)
	if n == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetLastError() (lasterr error) {
	r0, _, _ := syscall.I调用命令3(procGetLastError.I取命令地址(), 0, 0, 0, 0)
	if r0 != 0 {
		lasterr = syscall2.Errno(r0)
	}
	return
}

func GetLongPathName(path *uint16, buf *uint16, buflen uint32) (n uint32, err error) {
	r0, _, e1 := syscall.I调用命令3(procGetLongPathNameW.I取命令地址(), 3, uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(buf)), uintptr(buflen))
	n = uint32(r0)
	if n == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetProcAddress(module Handle, procname string) (proc uintptr, err error) {
	var _p0 *byte
	_p0, err = syscall2.BytePtrFromString(procname)
	if err != nil {
		return
	}
	return _GetProcAddress(module, _p0)
}

func _GetProcAddress(module Handle, procname *byte) (proc uintptr, err error) {
	r0, _, e1 := syscall.I调用命令3(procGetProcAddress.I取命令地址(), 2, uintptr(module), uintptr(unsafe.Pointer(procname)), 0)
	proc = uintptr(r0)
	if proc == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetProcessTimes(handle Handle, creationTime *Filetime, exitTime *Filetime, kernelTime *Filetime, userTime *Filetime) (err error) {
	r1, _, e1 := syscall.I调用命令6(procGetProcessTimes.I取命令地址(), 5, uintptr(handle), uintptr(unsafe.Pointer(creationTime)), uintptr(unsafe.Pointer(exitTime)), uintptr(unsafe.Pointer(kernelTime)), uintptr(unsafe.Pointer(userTime)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func getQueuedCompletionStatus(cphandle Handle, qty *uint32, key *uintptr, overlapped **Overlapped, timeout uint32) (err error) {
	r1, _, e1 := syscall.I调用命令6(procGetQueuedCompletionStatus.I取命令地址(), 5, uintptr(cphandle), uintptr(unsafe.Pointer(qty)), uintptr(unsafe.Pointer(key)), uintptr(unsafe.Pointer(overlapped)), uintptr(timeout), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetShortPathName(longpath *uint16, shortpath *uint16, buflen uint32) (n uint32, err error) {
	r0, _, e1 := syscall.I调用命令3(procGetShortPathNameW.I取命令地址(), 3, uintptr(unsafe.Pointer(longpath)), uintptr(unsafe.Pointer(shortpath)), uintptr(buflen))
	n = uint32(r0)
	if n == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetStartupInfo(startupInfo *StartupInfo) (err error) {
	r1, _, e1 := syscall.I调用命令3(procGetStartupInfoW.I取命令地址(), 1, uintptr(unsafe.Pointer(startupInfo)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetStdHandle(stdhandle int) (handle Handle, err error) {
	r0, _, e1 := syscall.I调用命令3(procGetStdHandle.I取命令地址(), 1, uintptr(stdhandle), 0, 0)
	handle = Handle(r0)
	if handle == InvalidHandle {
		err = errnoErr(e1)
	}
	return
}

func getSystemDirectory(dir *uint16, dirLen uint32) (len uint32, err error) {
	r0, _, e1 := syscall.I调用命令3(procGetSystemDirectoryW.I取命令地址(), 2, uintptr(unsafe.Pointer(dir)), uintptr(dirLen), 0)
	len = uint32(r0)
	if len == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetSystemTimeAsFileTime(time *Filetime) {
	syscall.I调用命令3(procGetSystemTimeAsFileTime.I取命令地址(), 1, uintptr(unsafe.Pointer(time)), 0, 0)
	return
}

func GetTempPath(buflen uint32, buf *uint16) (n uint32, err error) {
	r0, _, e1 := syscall.I调用命令3(procGetTempPathW.I取命令地址(), 2, uintptr(buflen), uintptr(unsafe.Pointer(buf)), 0)
	n = uint32(r0)
	if n == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetTimeZoneInformation(tzi *Timezoneinformation) (rc uint32, err error) {
	r0, _, e1 := syscall.I调用命令3(procGetTimeZoneInformation.I取命令地址(), 1, uintptr(unsafe.Pointer(tzi)), 0, 0)
	rc = uint32(r0)
	if rc == 0xffffffff {
		err = errnoErr(e1)
	}
	return
}

func GetVersion() (ver uint32, err error) {
	r0, _, e1 := syscall.I调用命令3(procGetVersion.I取命令地址(), 0, 0, 0, 0)
	ver = uint32(r0)
	if ver == 0 {
		err = errnoErr(e1)
	}
	return
}

func initializeProcThreadAttributeList(attrlist *_PROC_THREAD_ATTRIBUTE_LIST, attrcount uint32, flags uint32, size *uintptr) (err error) {
	r1, _, e1 := syscall.I调用命令6(procInitializeProcThreadAttributeList.I取命令地址(), 4, uintptr(unsafe.Pointer(attrlist)), uintptr(attrcount), uintptr(flags), uintptr(unsafe.Pointer(size)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func LoadLibrary(libname string) (handle Handle, err error) {
	var _p0 *uint16
	_p0, err = syscall.UTF16PtrFromString(libname)
	if err != nil {
		return
	}
	return _LoadLibrary(_p0)
}

func _LoadLibrary(libname *uint16) (handle Handle, err error) {
	r0, _, e1 := syscall.I调用命令3(procLoadLibraryW.I取命令地址(), 1, uintptr(unsafe.Pointer(libname)), 0, 0)
	handle = Handle(r0)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

func LocalFree(hmem Handle) (handle Handle, err error) {
	r0, _, e1 := syscall.I调用命令3(procLocalFree.I取命令地址(), 1, uintptr(hmem), 0, 0)
	handle = Handle(r0)
	if handle != 0 {
		err = errnoErr(e1)
	}
	return
}

func MapViewOfFile(handle Handle, access uint32, offsetHigh uint32, offsetLow uint32, length uintptr) (addr uintptr, err error) {
	r0, _, e1 := syscall.I调用命令6(procMapViewOfFile.I取命令地址(), 5, uintptr(handle), uintptr(access), uintptr(offsetHigh), uintptr(offsetLow), uintptr(length), 0)
	addr = uintptr(r0)
	if addr == 0 {
		err = errnoErr(e1)
	}
	return
}

func MoveFile(from *uint16, to *uint16) (err error) {
	r1, _, e1 := syscall.I调用命令3(procMoveFileW.I取命令地址(), 2, uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(to)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func OpenProcess(da uint32, inheritHandle bool, pid uint32) (handle Handle, err error) {
	var _p0 uint32
	if inheritHandle {
		_p0 = 1
	}
	r0, _, e1 := syscall.I调用命令3(procOpenProcess.I取命令地址(), 3, uintptr(da), uintptr(_p0), uintptr(pid))
	handle = Handle(r0)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

func postQueuedCompletionStatus(cphandle Handle, qty uint32, key uintptr, overlapped *Overlapped) (err error) {
	r1, _, e1 := syscall.I调用命令6(procPostQueuedCompletionStatus.I取命令地址(), 4, uintptr(cphandle), uintptr(qty), uintptr(key), uintptr(unsafe.Pointer(overlapped)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func Process32First(snapshot Handle, procEntry *ProcessEntry32) (err error) {
	r1, _, e1 := syscall.I调用命令3(procProcess32FirstW.I取命令地址(), 2, uintptr(snapshot), uintptr(unsafe.Pointer(procEntry)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func Process32Next(snapshot Handle, procEntry *ProcessEntry32) (err error) {
	r1, _, e1 := syscall.I调用命令3(procProcess32NextW.I取命令地址(), 2, uintptr(snapshot), uintptr(unsafe.Pointer(procEntry)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func ReadConsole(console Handle, buf *uint16, toread uint32, read *uint32, inputControl *byte) (err error) {
	r1, _, e1 := syscall.I调用命令6(procReadConsoleW.I取命令地址(), 5, uintptr(console), uintptr(unsafe.Pointer(buf)), uintptr(toread), uintptr(unsafe.Pointer(read)), uintptr(unsafe.Pointer(inputControl)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func ReadDirectoryChanges(handle Handle, buf *byte, buflen uint32, watchSubTree bool, mask uint32, retlen *uint32, overlapped *Overlapped, completionRoutine uintptr) (err error) {
	var _p0 uint32
	if watchSubTree {
		_p0 = 1
	}
	r1, _, e1 := syscall.I调用命令9(procReadDirectoryChangesW.I取命令地址(), 8, uintptr(handle), uintptr(unsafe.Pointer(buf)), uintptr(buflen), uintptr(_p0), uintptr(mask), uintptr(unsafe.Pointer(retlen)), uintptr(unsafe.Pointer(overlapped)), uintptr(completionRoutine), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func readFile(handle Handle, buf []byte, done *uint32, overlapped *Overlapped) (err error) {
	var _p0 *byte
	if len(buf) > 0 {
		_p0 = &buf[0]
	}
	r1, _, e1 := syscall.I调用命令6(procReadFile.I取命令地址(), 5, uintptr(handle), uintptr(unsafe.Pointer(_p0)), uintptr(len(buf)), uintptr(unsafe.Pointer(done)), uintptr(unsafe.Pointer(overlapped)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func RemoveDirectory(path *uint16) (err error) {
	r1, _, e1 := syscall.I调用命令3(procRemoveDirectoryW.I取命令地址(), 1, uintptr(unsafe.Pointer(path)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetCurrentDirectory(path *uint16) (err error) {
	r1, _, e1 := syscall.I调用命令3(procSetCurrentDirectoryW.I取命令地址(), 1, uintptr(unsafe.Pointer(path)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetEndOfFile(handle Handle) (err error) {
	r1, _, e1 := syscall.I调用命令3(procSetEndOfFile.I取命令地址(), 1, uintptr(handle), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetEnvironmentVariable(name *uint16, value *uint16) (err error) {
	r1, _, e1 := syscall.I调用命令3(procSetEnvironmentVariableW.I取命令地址(), 2, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(value)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetFileAttributes(name *uint16, attrs uint32) (err error) {
	r1, _, e1 := syscall.I调用命令3(procSetFileAttributesW.I取命令地址(), 2, uintptr(unsafe.Pointer(name)), uintptr(attrs), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetFileCompletionNotificationModes(handle Handle, flags uint8) (err error) {
	r1, _, e1 := syscall.I调用命令3(procSetFileCompletionNotificationModes.I取命令地址(), 2, uintptr(handle), uintptr(flags), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetFilePointer(handle Handle, lowoffset int32, highoffsetptr *int32, whence uint32) (newlowoffset uint32, err error) {
	r0, _, e1 := syscall.I调用命令6(procSetFilePointer.I取命令地址(), 4, uintptr(handle), uintptr(lowoffset), uintptr(unsafe.Pointer(highoffsetptr)), uintptr(whence), 0, 0)
	newlowoffset = uint32(r0)
	if newlowoffset == 0xffffffff {
		err = errnoErr(e1)
	}
	return
}

func SetFileTime(handle Handle, ctime *Filetime, atime *Filetime, wtime *Filetime) (err error) {
	r1, _, e1 := syscall.I调用命令6(procSetFileTime.I取命令地址(), 4, uintptr(handle), uintptr(unsafe.Pointer(ctime)), uintptr(unsafe.Pointer(atime)), uintptr(unsafe.Pointer(wtime)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetHandleInformation(handle Handle, mask uint32, flags uint32) (err error) {
	r1, _, e1 := syscall.I调用命令3(procSetHandleInformation.I取命令地址(), 3, uintptr(handle), uintptr(mask), uintptr(flags))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func TerminateProcess(handle Handle, exitcode uint32) (err error) {
	r1, _, e1 := syscall.I调用命令3(procTerminateProcess.I取命令地址(), 2, uintptr(handle), uintptr(exitcode), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func UnmapViewOfFile(addr uintptr) (err error) {
	r1, _, e1 := syscall.I调用命令3(procUnmapViewOfFile.I取命令地址(), 1, uintptr(addr), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func updateProcThreadAttribute(attrlist *_PROC_THREAD_ATTRIBUTE_LIST, flags uint32, attr uintptr, value unsafe.Pointer, size uintptr, prevvalue unsafe.Pointer, returnedsize *uintptr) (err error) {
	r1, _, e1 := syscall.I调用命令9(procUpdateProcThreadAttribute.I取命令地址(), 7, uintptr(unsafe.Pointer(attrlist)), uintptr(flags), uintptr(attr), uintptr(value), uintptr(size), uintptr(prevvalue), uintptr(unsafe.Pointer(returnedsize)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func VirtualLock(addr uintptr, length uintptr) (err error) {
	r1, _, e1 := syscall.I调用命令3(procVirtualLock.I取命令地址(), 2, uintptr(addr), uintptr(length), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func VirtualUnlock(addr uintptr, length uintptr) (err error) {
	r1, _, e1 := syscall.I调用命令3(procVirtualUnlock.I取命令地址(), 2, uintptr(addr), uintptr(length), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func WaitForSingleObject(handle Handle, waitMilliseconds uint32) (event uint32, err error) {
	r0, _, e1 := syscall.I调用命令3(procWaitForSingleObject.I取命令地址(), 2, uintptr(handle), uintptr(waitMilliseconds), 0)
	event = uint32(r0)
	if event == 0xffffffff {
		err = errnoErr(e1)
	}
	return
}

func WriteConsole(console Handle, buf *uint16, towrite uint32, written *uint32, reserved *byte) (err error) {
	r1, _, e1 := syscall.I调用命令6(procWriteConsoleW.I取命令地址(), 5, uintptr(console), uintptr(unsafe.Pointer(buf)), uintptr(towrite), uintptr(unsafe.Pointer(written)), uintptr(unsafe.Pointer(reserved)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func writeFile(handle Handle, buf []byte, done *uint32, overlapped *Overlapped) (err error) {
	var _p0 *byte
	if len(buf) > 0 {
		_p0 = &buf[0]
	}
	r1, _, e1 := syscall.I调用命令6(procWriteFile.I取命令地址(), 5, uintptr(handle), uintptr(unsafe.Pointer(_p0)), uintptr(len(buf)), uintptr(unsafe.Pointer(done)), uintptr(unsafe.Pointer(overlapped)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func AcceptEx(ls Handle, as Handle, buf *byte, rxdatalen uint32, laddrlen uint32, raddrlen uint32, recvd *uint32, overlapped *Overlapped) (err error) {
	r1, _, e1 := syscall.I调用命令9(procAcceptEx.I取命令地址(), 8, uintptr(ls), uintptr(as), uintptr(unsafe.Pointer(buf)), uintptr(rxdatalen), uintptr(laddrlen), uintptr(raddrlen), uintptr(unsafe.Pointer(recvd)), uintptr(unsafe.Pointer(overlapped)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetAcceptExSockaddrs(buf *byte, rxdatalen uint32, laddrlen uint32, raddrlen uint32, lrsa **RawSockaddrAny, lrsalen *int32, rrsa **RawSockaddrAny, rrsalen *int32) {
	syscall.I调用命令9(procGetAcceptExSockaddrs.I取命令地址(), 8, uintptr(unsafe.Pointer(buf)), uintptr(rxdatalen), uintptr(laddrlen), uintptr(raddrlen), uintptr(unsafe.Pointer(lrsa)), uintptr(unsafe.Pointer(lrsalen)), uintptr(unsafe.Pointer(rrsa)), uintptr(unsafe.Pointer(rrsalen)), 0)
	return
}

func TransmitFile(s Handle, handle Handle, bytesToWrite uint32, bytsPerSend uint32, overlapped *Overlapped, transmitFileBuf *TransmitFileBuffers, flags uint32) (err error) {
	r1, _, e1 := syscall.I调用命令9(procTransmitFile.I取命令地址(), 7, uintptr(s), uintptr(handle), uintptr(bytesToWrite), uintptr(bytsPerSend), uintptr(unsafe.Pointer(overlapped)), uintptr(unsafe.Pointer(transmitFileBuf)), uintptr(flags), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func NetApiBufferFree(buf *byte) (neterr error) {
	r0, _, _ := syscall.I调用命令3(procNetApiBufferFree.I取命令地址(), 1, uintptr(unsafe.Pointer(buf)), 0, 0)
	if r0 != 0 {
		neterr = syscall2.Errno(r0)
	}
	return
}

func NetGetJoinInformation(server *uint16, name **uint16, bufType *uint32) (neterr error) {
	r0, _, _ := syscall.I调用命令3(procNetGetJoinInformation.I取命令地址(), 3, uintptr(unsafe.Pointer(server)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(bufType)))
	if r0 != 0 {
		neterr = syscall2.Errno(r0)
	}
	return
}

func NetUserGetInfo(serverName *uint16, userName *uint16, level uint32, buf **byte) (neterr error) {
	r0, _, _ := syscall.I调用命令6(procNetUserGetInfo.I取命令地址(), 4, uintptr(unsafe.Pointer(serverName)), uintptr(unsafe.Pointer(userName)), uintptr(level), uintptr(unsafe.Pointer(buf)), 0, 0)
	if r0 != 0 {
		neterr = syscall2.Errno(r0)
	}
	return
}

func rtlGetNtVersionNumbers(majorVersion *uint32, minorVersion *uint32, buildNumber *uint32) {
	syscall.I调用命令3(procRtlGetNtVersionNumbers.I取命令地址(), 3, uintptr(unsafe.Pointer(majorVersion)), uintptr(unsafe.Pointer(minorVersion)), uintptr(unsafe.Pointer(buildNumber)))
	return
}

func GetUserNameEx(nameFormat uint32, nameBuffre *uint16, nSize *uint32) (err error) {
	r1, _, e1 := syscall.I调用命令3(procGetUserNameExW.I取命令地址(), 3, uintptr(nameFormat), uintptr(unsafe.Pointer(nameBuffre)), uintptr(unsafe.Pointer(nSize)))
	if r1&0xff == 0 {
		err = errnoErr(e1)
	}
	return
}

func TranslateName(accName *uint16, accNameFormat uint32, desiredNameFormat uint32, translatedName *uint16, nSize *uint32) (err error) {
	r1, _, e1 := syscall.I调用命令6(procTranslateNameW.I取命令地址(), 5, uintptr(unsafe.Pointer(accName)), uintptr(accNameFormat), uintptr(desiredNameFormat), uintptr(unsafe.Pointer(translatedName)), uintptr(unsafe.Pointer(nSize)), 0)
	if r1&0xff == 0 {
		err = errnoErr(e1)
	}
	return
}

func CommandLineToArgv(cmd *uint16, argc *int32) (argv *[8192]*[8192]uint16, err error) {
	r0, _, e1 := syscall.I调用命令3(procCommandLineToArgvW.I取命令地址(), 2, uintptr(unsafe.Pointer(cmd)), uintptr(unsafe.Pointer(argc)), 0)
	argv = (*[8192]*[8192]uint16)(unsafe.Pointer(r0))
	if argv == nil {
		err = errnoErr(e1)
	}
	return
}

func GetUserProfileDirectory(t Token, dir *uint16, dirLen *uint32) (err error) {
	r1, _, e1 := syscall.I调用命令3(procGetUserProfileDirectoryW.I取命令地址(), 3, uintptr(t), uintptr(unsafe.Pointer(dir)), uintptr(unsafe.Pointer(dirLen)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func FreeAddrInfoW(addrinfo *AddrinfoW) {
	syscall.I调用命令3(procFreeAddrInfoW.I取命令地址(), 1, uintptr(unsafe.Pointer(addrinfo)), 0, 0)
	return
}

func GetAddrInfoW(nodename *uint16, servicename *uint16, hints *AddrinfoW, result **AddrinfoW) (sockerr error) {
	r0, _, _ := syscall.I调用命令6(procGetAddrInfoW.I取命令地址(), 4, uintptr(unsafe.Pointer(nodename)), uintptr(unsafe.Pointer(servicename)), uintptr(unsafe.Pointer(hints)), uintptr(unsafe.Pointer(result)), 0, 0)
	if r0 != 0 {
		sockerr = syscall2.Errno(r0)
	}
	return
}

func WSACleanup() (err error) {
	r1, _, e1 := syscall.I调用命令3(procWSACleanup.I取命令地址(), 0, 0, 0, 0)
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func WSAEnumProtocols(protocols *int32, protocolBuffer *WSAProtocolInfo, bufferLength *uint32) (n int32, err error) {
	r0, _, e1 := syscall.I调用命令3(procWSAEnumProtocolsW.I取命令地址(), 3, uintptr(unsafe.Pointer(protocols)), uintptr(unsafe.Pointer(protocolBuffer)), uintptr(unsafe.Pointer(bufferLength)))
	n = int32(r0)
	if n == -1 {
		err = errnoErr(e1)
	}
	return
}

func WSAIoctl(s Handle, iocc uint32, inbuf *byte, cbif uint32, outbuf *byte, cbob uint32, cbbr *uint32, overlapped *Overlapped, completionRoutine uintptr) (err error) {
	r1, _, e1 := syscall.I调用命令9(procWSAIoctl.I取命令地址(), 9, uintptr(s), uintptr(iocc), uintptr(unsafe.Pointer(inbuf)), uintptr(cbif), uintptr(unsafe.Pointer(outbuf)), uintptr(cbob), uintptr(unsafe.Pointer(cbbr)), uintptr(unsafe.Pointer(overlapped)), uintptr(completionRoutine))
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func WSARecv(s Handle, bufs *WSABuf, bufcnt uint32, recvd *uint32, flags *uint32, overlapped *Overlapped, croutine *byte) (err error) {
	r1, _, e1 := syscall.I调用命令9(procWSARecv.I取命令地址(), 7, uintptr(s), uintptr(unsafe.Pointer(bufs)), uintptr(bufcnt), uintptr(unsafe.Pointer(recvd)), uintptr(unsafe.Pointer(flags)), uintptr(unsafe.Pointer(overlapped)), uintptr(unsafe.Pointer(croutine)), 0, 0)
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func WSARecvFrom(s Handle, bufs *WSABuf, bufcnt uint32, recvd *uint32, flags *uint32, from *RawSockaddrAny, fromlen *int32, overlapped *Overlapped, croutine *byte) (err error) {
	r1, _, e1 := syscall.I调用命令9(procWSARecvFrom.I取命令地址(), 9, uintptr(s), uintptr(unsafe.Pointer(bufs)), uintptr(bufcnt), uintptr(unsafe.Pointer(recvd)), uintptr(unsafe.Pointer(flags)), uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(fromlen)), uintptr(unsafe.Pointer(overlapped)), uintptr(unsafe.Pointer(croutine)))
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func WSASend(s Handle, bufs *WSABuf, bufcnt uint32, sent *uint32, flags uint32, overlapped *Overlapped, croutine *byte) (err error) {
	r1, _, e1 := syscall.I调用命令9(procWSASend.I取命令地址(), 7, uintptr(s), uintptr(unsafe.Pointer(bufs)), uintptr(bufcnt), uintptr(unsafe.Pointer(sent)), uintptr(flags), uintptr(unsafe.Pointer(overlapped)), uintptr(unsafe.Pointer(croutine)), 0, 0)
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func WSASendTo(s Handle, bufs *WSABuf, bufcnt uint32, sent *uint32, flags uint32, to *RawSockaddrAny, tolen int32, overlapped *Overlapped, croutine *byte) (err error) {
	r1, _, e1 := syscall.I调用命令9(procWSASendTo.I取命令地址(), 9, uintptr(s), uintptr(unsafe.Pointer(bufs)), uintptr(bufcnt), uintptr(unsafe.Pointer(sent)), uintptr(flags), uintptr(unsafe.Pointer(to)), uintptr(tolen), uintptr(unsafe.Pointer(overlapped)), uintptr(unsafe.Pointer(croutine)))
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func WSAStartup(verreq uint32, data *WSAData) (sockerr error) {
	r0, _, _ := syscall.I调用命令3(procWSAStartup.I取命令地址(), 2, uintptr(verreq), uintptr(unsafe.Pointer(data)), 0)
	if r0 != 0 {
		sockerr = syscall2.Errno(r0)
	}
	return
}

func bind(s uintptr, name unsafe.Pointer, namelen int32) (err error) {
	r1, _, e1 := syscall.I调用命令3(procbind.I取命令地址(), 3, uintptr(s), uintptr(name), uintptr(namelen))
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func Closesocket(s uintptr) (err error) {
	r1, _, e1 := syscall.I调用命令3(procclosesocket.I取命令地址(), 1, uintptr(s), 0, 0)
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func connect(s uintptr, name unsafe.Pointer, namelen int32) (err error) {
	r1, _, e1 := syscall.I调用命令3(procconnect.I取命令地址(), 3, uintptr(s), uintptr(name), uintptr(namelen))
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func GetHostByName(name string) (h *Hostent, err error) {
	var _p0 *byte
	_p0, err = syscall2.BytePtrFromString(name)
	if err != nil {
		return
	}
	return _GetHostByName(_p0)
}

func _GetHostByName(name *byte) (h *Hostent, err error) {
	r0, _, e1 := syscall.I调用命令3(procgethostbyname.I取命令地址(), 1, uintptr(unsafe.Pointer(name)), 0, 0)
	h = (*Hostent)(unsafe.Pointer(r0))
	if h == nil {
		err = errnoErr(e1)
	}
	return
}

func getpeername(s uintptr, rsa *RawSockaddrAny, addrlen *int32) (err error) {
	r1, _, e1 := syscall.I调用命令3(procgetpeername.I取命令地址(), 3, uintptr(s), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)))
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func GetProtoByName(name string) (p *Protoent, err error) {
	var _p0 *byte
	_p0, err = syscall2.BytePtrFromString(name)
	if err != nil {
		return
	}
	return _GetProtoByName(_p0)
}

func _GetProtoByName(name *byte) (p *Protoent, err error) {
	r0, _, e1 := syscall.I调用命令3(procgetprotobyname.I取命令地址(), 1, uintptr(unsafe.Pointer(name)), 0, 0)
	p = (*Protoent)(unsafe.Pointer(r0))
	if p == nil {
		err = errnoErr(e1)
	}
	return
}

func GetServByName(name string, proto string) (s *Servent, err error) {
	var _p0 *byte
	_p0, err = syscall2.BytePtrFromString(name)
	if err != nil {
		return
	}
	var _p1 *byte
	_p1, err = syscall2.BytePtrFromString(proto)
	if err != nil {
		return
	}
	return _GetServByName(_p0, _p1)
}

func _GetServByName(name *byte, proto *byte) (s *Servent, err error) {
	r0, _, e1 := syscall.I调用命令3(procgetservbyname.I取命令地址(), 2, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(proto)), 0)
	s = (*Servent)(unsafe.Pointer(r0))
	if s == nil {
		err = errnoErr(e1)
	}
	return
}

func getsockname(s uintptr, rsa *RawSockaddrAny, addrlen *int32) (err error) {
	r1, _, e1 := syscall.I调用命令3(procgetsockname.I取命令地址(), 3, uintptr(s), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)))
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func Getsockopt(s uintptr, level int32, optname int32, optval *byte, optlen *int32) (err error) {
	r1, _, e1 := syscall.I调用命令6(procgetsockopt.I取命令地址(), 5, uintptr(s), uintptr(level), uintptr(optname), uintptr(unsafe.Pointer(optval)), uintptr(unsafe.Pointer(optlen)), 0)
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func listen(s uintptr, backlog int32) (err error) {
	r1, _, e1 := syscall.I调用命令3(proclisten.I取命令地址(), 2, uintptr(s), uintptr(backlog), 0)
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func Ntohs(netshort uint16) (u uint16) {
	r0, _, _ := syscall.I调用命令3(procntohs.I取命令地址(), 1, uintptr(netshort), 0, 0)
	u = uint16(r0)
	return
}

func Setsockopt(s uintptr, level int32, optname int32, optval *byte, optlen int32) (err error) {
	r1, _, e1 := syscall.I调用命令6(procsetsockopt.I取命令地址(), 5, uintptr(s), uintptr(level), uintptr(optname), uintptr(unsafe.Pointer(optval)), uintptr(optlen), 0)
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func shutdown(s uintptr, how int32) (err error) {
	r1, _, e1 := syscall.I调用命令3(procshutdown.I取命令地址(), 2, uintptr(s), uintptr(how), 0)
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}
