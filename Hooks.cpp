#include <Windows.h>
#include <stdio.h>

typedef BOOL(*SetHook)();
typedef BOOL(*UnHook)();


BOOL GlobalHook(BOOL isSet) {
	HMODULE hModule = LoadLibrary(L"NotepadHook.dll");
	if (!hModule)
	{
		printf("LoadLibrary Error:%d", GetLastError());
		return FALSE;
	}

	if (isSet == TRUE)
	{
		SetHook sethook = (SetHook)GetProcAddress(hModule, "SetGlobalHook");
		if (!sethook)
		{
			printf("GetProcAddress SetGlobalHook Error:%d", GetLastError());
			return FALSE;
		}
		sethook();
		return TRUE;
	}
	else
	{
		UnHook unhook = (UnHook)GetProcAddress(hModule, "UnsetGlobalHook");
		if (!unhook)
		{
			printf("GetProcAddress UnsetGlobalHook Error:%d", GetLastError());
			return FALSE;
		}
		unhook();
		return TRUE;
	}

}

int main(int argc, char* argv[]) {
	//延迟释放：就是把dll编译进资源文件里面，在执行的时候释放
	HRSRC hRsrc = FindResource(0, (LPCWSTR)101, L"MYDLL");
	if (!hRsrc)
	{
		printf("FindResource Error:%d", GetLastError());
		return FALSE;
	}

	DWORD dwSize = SizeofResource(NULL, hRsrc);
	if (!dwSize)
	{
		printf("SizeofResource Error:%d", GetLastError());
		return FALSE;
	}

	HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
	if (!hGlobal)
	{
		printf("LoadResource Error:%d", GetLastError());
		return FALSE;
	}

	LPVOID lpVoid = LockResource(hGlobal);
	if (!lpVoid)
	{
		printf("LockResource Error:%d", GetLastError());
		return FALSE;
	}

	FILE* fp = NULL;
	fopen_s(&fp, "GlobalHool.dll", "wb+");
	fwrite(lpVoid, sizeof(char), dwSize, fp);
	fclose(fp);

	BOOL bRet = NULL;
	bRet = GlobalHook(TRUE);
	if (!bRet)
	{
		printf("SetGlobalHook Error:%d", GetLastError());
		return FALSE;
	}
	system("pause");
	bRet = GlobalHook(FALSE);
	if (!bRet)
	{
		printf("UnSetGlobalHook Error:%d", GetLastError());
		return FALSE;
	}
	system("pause");
	return 0;

}
