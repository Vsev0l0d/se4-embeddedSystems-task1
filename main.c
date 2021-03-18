#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include <io.h>
#include <fcntl.h>

int main() {
    LPCSTR fileName = "untitled.exe"; //exe file to parse
    HANDLE hFile;
    HANDLE hFileMapping;
    LPVOID lpFileBase;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeader;
    PIMAGE_SECTION_HEADER sectionHeader;
    hFile = CreateFileA(fileName,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
    if (hFile != INVALID_HANDLE_VALUE) {
        hFileMapping = CreateFileMapping(hFile,NULL,PAGE_READONLY,0,0,NULL);
        if (hFileMapping != 0) {
            lpFileBase = MapViewOfFile(hFileMapping,FILE_MAP_READ,0,0,0);
            if (lpFileBase != 0) {
                dosHeader = (PIMAGE_DOS_HEADER) lpFileBase;  //pointer to dos headers
                if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
                    ntHeader = (PIMAGE_NT_HEADERS) ((u_char*)dosHeader + dosHeader->e_lfanew);
                    if (ntHeader->Signature == IMAGE_NT_SIGNATURE) {
                        FILE *outInf, *outCode;
                        outInf = fopen("inf.txt", "w");
                        outCode = fopen("code.bin", "wb");

                        DWORD addressEntryPoint = ntHeader->OptionalHeader.AddressOfEntryPoint;
                        fprintf(outInf, "%s%lu\n", "Address of entry point: ", addressEntryPoint);
                        sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
//                        DWORD firstSection = dosHeader->e_lfanew + ntHeader->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD);
                        for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, sectionHeader++) {
                            fprintf(outInf, "%s%d\n", "Section", i + 1);
                            fprintf(outInf, "%s%s\n", "Name: ", sectionHeader->Name);
                            fprintf(outInf, "%s%lu\n", "Virtual Address: ", sectionHeader->VirtualAddress);
                            fprintf(outInf, "%s%lu\n", "Raw Size: ", sectionHeader->SizeOfRawData);
                            fprintf(outInf, "%s%lu\n", "Virtual Size: ", sectionHeader->Misc.VirtualSize);
                            fprintf(outInf, "%s%lu\n", "Physical Address: ", sectionHeader->Misc.PhysicalAddress);
                            fprintf(outInf, "%s%hu\n", "Number of line numbers: ", sectionHeader->NumberOfLinenumbers);
                            fprintf(outInf, "%s%hu\n", "Number of relocations: ", sectionHeader->NumberOfRelocations);
                            fprintf(outInf, "%s%lu\n", "Pointer to line numbers: ", sectionHeader->PointerToLinenumbers);
                            fprintf(outInf, "%s%lu\n", "Number to relocations: ", sectionHeader->PointerToRelocations);
                            fprintf(outInf, "%s%lu\n", "Number to raw data: ", sectionHeader->PointerToRawData);
                            fprintf(outInf, "%s%lu\n\n", "Characteristics: ", sectionHeader->Characteristics);

                            if (sectionHeader->Characteristics & IMAGE_SCN_CNT_CODE){
                                fprintf(outCode, "%s%d\n", "Section", i + 1); //use PointerToRawData
                            }
                        }
                        fclose(outInf);
                        fclose(outCode);
                    }
                }
            }
        }
    }















//    FILE *fp1, *fp2;
//    fp1 = fopen("untitled.exe", "rb");
//    int input = open("untitled.exe", O_RDONLY | O_BINARY);
//    printf("%d", input);
//    if (input != -1) {
//        printf("%s\n", "START");
//        IMAGE_DOS_HEADER dos_header;
//        read(input, &dos_header, sizeof(IMAGE_DOS_HEADER));
//        //проверка dos_signature
//        if (dos_header.e_magic == 23117) printf("%s", "MZ");
//        if (dos_header.e_lfanew % sizeof(DWORD) != 0) {
//            printf("PE header is not aligned");
//        }
//        input = dos_header.e_lfanew;
//        IMAGE_NT_HEADERS32 nt_header;
//        read(input, &nt_header, sizeof(IMAGE_NT_HEADERS32) - sizeof(IMAGE_DATA_DIRECTORY) * 16);
//        printf("\n%d", IMAGE_NT_SIGNATURE);
//        printf("\n%lu", nt_header.Signature);
////        if (nt_header.Signature == I) {
////            printf("%s", "PE");
////        }
//    } else {
//    }
//    fp1 = fopen("sex.exe", "rb");
//    if ((fp1 = fopen("sex.exe", "rb")) != NULL) {
//        fp2 = fopen("inf.txt", "w");
//        int64_t _file_size = 0;
//        fseek(fp1, 0, SEEK_END);
//        _file_size = ftello(fp1);
//        fseek(fp1, 0, SEEK_SET);

//        char elem;
//        fscanf(fp1, "%c", &elem);
//        while (!feof(fp1)){
//            fprintf(fp2, "%c", elem);
//            fscanf(fp1, "%c", &elem);
//        }
//        fseek(fp1, 0, SEEK_SET);
//
//        fseek(fp1, dos_header.e_lfanew, SEEK_SET);
//
//        IMAGE_NT_HEADERS32 nt_headers;
//        read(fp1, &nt_headers, sizeof(IMAGE_NT_HEADERS32) - sizeof(IMAGE_DATA_DIRECTORY) * 16);
//
//        printf("%d\n", nt_headers.Signature);
//        printf("%d", dos_header.e_magic);
//
//        fclose(fp1);
//        fclose(fp2);
//    }

}
