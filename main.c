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
            FILE *outInf, *outCode;
            outInf = fopen("inf.txt", "w");
            outCode = fopen("code.bin", "wb");

            fseek(fileReader, dosHeader.e_lfanew, SEEK_SET);
            IMAGE_NT_HEADERS ntHeaders;
            fread(&ntHeaders, sizeof(IMAGE_NT_HEADERS), 1, fileReader);
            WORD addressEntryPoint = ntHeaders.OptionalHeader.AddressOfEntryPoint;
            fprintf(outInf, "%s%hX\n", "Address of entry point: 0x", addressEntryPoint);
            IMAGE_SECTION_HEADER currentSection;
            for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
                fread(&currentSection, sizeof(IMAGE_SECTION_HEADER), 1, fileReader);
                fprintf(outInf, "%s%d\n", "Section", i + 1);
                fprintf(outInf, "%s%s\n", "Name: ", currentSection.Name);
                fprintf(outInf, "%s%lX\n", "Virtual Address: 0x", currentSection.VirtualAddress);
                fprintf(outInf, "%s%lX\n", "Raw Size: 0x", currentSection.SizeOfRawData);
                fprintf(outInf, "%s%lX\n", "Virtual Size: 0x", currentSection.Misc.VirtualSize);
                fprintf(outInf, "%s%lX\n", "Physical Address: 0x", currentSection.Misc.PhysicalAddress);
                fprintf(outInf, "%s%hX\n", "Number of line numbers: 0x", currentSection.NumberOfLinenumbers);
                fprintf(outInf, "%s%hX\n", "Number of relocations: 0x", currentSection.NumberOfRelocations);
                fprintf(outInf, "%s%lX\n", "Pointer to line numbers: 0x", currentSection.PointerToLinenumbers);
                fprintf(outInf, "%s%lX\n", "Number to relocations: 0x", currentSection.PointerToRelocations);
                fprintf(outInf, "%s%lX\n", "Number to raw data: 0x", currentSection.PointerToRawData);
                fprintf(outInf, "%s%lX\n\n", "Characteristics: 0x", currentSection.Characteristics);

                if (currentSection.Characteristics & IMAGE_SCN_CNT_CODE) {
                    int seekLast = ftell(fileReader);
                    fseek(fileReader, currentSection.PointerToRawData, SEEK_SET);
                    char buff[currentSection.SizeOfRawData];
                    fread(buff, sizeof(char), currentSection.SizeOfRawData, fileReader);
                    fwrite(buff, sizeof(char), currentSection.SizeOfRawData, outCode);
                    fseek(fileReader, seekLast, SEEK_SET);
                }
            }
            fclose(outInf);
            fclose(outCode);
            fclose(fileReader);
        }
    }
}
