#include <stdio.h>
#include <stdint.h>
#include <windows.h>

int main() {
    FILE* fileReader = fopen("se4_embeddedSystems_task1.exe", "rb");
    if (fileReader == NULL) {
        printf("Cannot open file se4_embeddedSystems_task1.exe");
    } else {
        IMAGE_DOS_HEADER dosHeader;
        fread(&dosHeader, sizeof (IMAGE_DOS_HEADER), 1, fileReader);
        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            printf("Image Dos Signature is incorrect!");
        } else {
            fseek(fileReader, dosHeader.e_lfanew, SEEK_SET);
            IMAGE_NT_HEADERS ntHeaders;
            fread(&ntHeaders, sizeof(IMAGE_NT_HEADERS), 1, fileReader);
            WORD addressEntryPoint = ntHeaders.OptionalHeader.AddressOfEntryPoint;
            IMAGE_SECTION_HEADER currentSection;
            FILE *outInf, *outCode;
            outInf = fopen("inf.txt", "w");
            outCode = fopen("code.bin", "wb");
            fprintf(outInf, "%s%hu\n", "Address of entry point: ", addressEntryPoint);
            for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
                fread(&currentSection, sizeof(IMAGE_SECTION_HEADER), 1, fileReader);
                fprintf(outInf, "%s%d\n", "Section", i + 1);
                fprintf(outInf, "%s%s\n", "Name: ", currentSection.Name);
                fprintf(outInf, "%s%lu\n", "Virtual Address: ", currentSection.VirtualAddress);
                fprintf(outInf, "%s%lu\n", "Raw Size: ", currentSection.SizeOfRawData);
                fprintf(outInf, "%s%lu\n", "Virtual Size: ", currentSection.Misc.VirtualSize);
                fprintf(outInf, "%s%lu\n", "Physical Address: ", currentSection.Misc.PhysicalAddress);
                fprintf(outInf, "%s%hu\n", "Number of line numbers: ", currentSection.NumberOfLinenumbers);
                fprintf(outInf, "%s%hu\n", "Number of relocations: ", currentSection.NumberOfRelocations);
                fprintf(outInf, "%s%lu\n", "Pointer to line numbers: ", currentSection.PointerToLinenumbers);
                fprintf(outInf, "%s%lu\n", "Number to relocations: ", currentSection.PointerToRelocations);
                fprintf(outInf, "%s%lu\n", "Number to raw data: ", currentSection.PointerToRawData);
                fprintf(outInf, "%s%lX\n\n", "Characteristics: 0x", currentSection.Characteristics);

                if (currentSection.Characteristics & IMAGE_SCN_CNT_CODE) {
                    fprintf(outCode, "%s%d\n", "Section", i + 1); //use PointerToRawData
                }
            }
            fclose(outInf);
            fclose(outCode);
        }
    }
}
