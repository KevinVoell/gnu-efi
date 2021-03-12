#include <efi.h>
#include <efilib.h>
#include <elf.h>

typedef unsigned long long size_t;

typedef struct {
	void* BaseAddress;
	size_t BufferSize;
	unsigned int Width;
	unsigned int Height;
	unsigned int PixelsPerScanLine;
} FrameBuffer;

#define PSF1_MAGIC0 0x36
#define PSF1_MAGIC1 0x04

typedef struct {
	unsigned char magic[2];
	unsigned char mode;
	unsigned char charsize;

} PSF1_HEADER;

typedef struct {
	PSF1_HEADER* psf1_header;
	void* glyphBuffer;
} PSF1_FONT;

typedef struct {
	FrameBuffer* frameBuffer;
	PSF1_FONT* psf1_Font;
	EFI_MEMORY_DESCRIPTOR* memMap;
	UINTN memMapSize;
	UINTN memDescriptorSize;
	void* rsdp;
} BootInfo;

FrameBuffer frameBuffer;

FrameBuffer* InitializeGOP() {
	EFI_GUID gopGuid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;

	EFI_GRAPHICS_OUTPUT_PROTOCOL* gop;
	EFI_STATUS status;

	status = uefi_call_wrapper(BS->LocateProtocol, 3, &gopGuid, NULL, (void**)&gop);
	if (EFI_ERROR(status)){
		Print(L"Unable to locate GOP");
		return NULL;
	}

	frameBuffer.BaseAddress = (void*)gop->Mode->FrameBufferBase;
	frameBuffer.BufferSize = gop->Mode->FrameBufferSize;
	frameBuffer.Width = gop->Mode->Info->HorizontalResolution;
	frameBuffer.Height = gop->Mode->Info->VerticalResolution;
	frameBuffer.PixelsPerScanLine = gop->Mode->Info->PixelsPerScanLine;

	Print(L"GOP Located");

	return &frameBuffer;
}

/*

 */
EFI_FILE* LoadFile(EFI_FILE* Directory, CHAR16* Path, EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable){
	EFI_FILE* loadedFile;

	EFI_LOADED_IMAGE_PROTOCOL* loadedImage;
	SystemTable->BootServices->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, (void**)&loadedImage);

	EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* fileSystem;
	SystemTable->BootServices->HandleProtocol(loadedImage->DeviceHandle, &gEfiSimpleFileSystemProtocolGuid, (void**)&fileSystem);

	if (Directory == NULL) {
		fileSystem->OpenVolume(fileSystem, &Directory);
	}

	EFI_STATUS s = Directory->Open(Directory, &loadedFile, Path, EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY);
	if (s != EFI_SUCCESS) {
		return NULL;
	}

	return loadedFile;
}

PSF1_FONT* LoadPSF1Font(EFI_FILE* Directory, CHAR16* Path, EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable){
	EFI_FILE* font = LoadFile(Directory, Path, ImageHandle, SystemTable);
	if (font == NULL){
		return NULL;
	}

	PSF1_HEADER* fontHeader;
	SystemTable->BootServices->AllocatePool(EfiLoaderData, sizeof(PSF1_HEADER), (void**)&fontHeader);
	UINTN size = sizeof(PSF1_HEADER);
	font->Read(font, &size, fontHeader);

	if (fontHeader->magic[0] != PSF1_MAGIC0 || fontHeader->magic[1] != PSF1_MAGIC1) {
		return NULL;
	}

	UINTN glyphBufferSize = fontHeader->charsize * 256;
	if (fontHeader->mode == 1) {
		glyphBufferSize = fontHeader->charsize * 512;
	}

	void* glyphBuffer;
	font->SetPosition(font, sizeof(PSF1_HEADER));
	SystemTable->BootServices->AllocatePool(EfiLoaderData, glyphBufferSize, (void**)&glyphBuffer);
	font->Read(font, &glyphBufferSize, glyphBuffer);

	PSF1_FONT* finishedFont;
	SystemTable->BootServices->AllocatePool(EfiLoaderData, sizeof(PSF1_FONT), (void**)&finishedFont);
	finishedFont->psf1_header = fontHeader;
	finishedFont->glyphBuffer = glyphBuffer;

	return finishedFont;
}

int memcmp(const void* aptr, const void* bptr, size_t n) {
	const unsigned char* a= aptr, *b= bptr;
	for (size_t i = 0; i < n; i++) {
		if (a[i] < b[i]) return -1;
		else if (a[i] > b[i]) return 1;
	}

	return 0;
}

UINTN strcmp(CHAR8* a, CHAR8* b, UINTN length){
	for (UINTN i = 0; i < length; i++){
		if (*a != *b) return 0;
	}

	return 1;
}

EFI_STATUS efi_main (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
	InitializeLib(ImageHandle, SystemTable);

	EFI_FILE* kernel = LoadFile(NULL, L"kernel.elf", ImageHandle, SystemTable);
	if (kernel == NULL){
		Print(L"Could not load kernel \n\r");
	} else {
		Print(L"Kernel loaded successfully \n\r");
	}

	Elf64_Ehdr header;
	{
		UINTN FileInfoSize;
		EFI_FILE_INFO* FileInfo;
		kernel->GetInfo(kernel,&gEfiFileInfoGuid, &FileInfoSize, NULL);
		SystemTable->BootServices->AllocatePool(EfiLoaderData, FileInfoSize, (void**)&FileInfo);
		kernel->GetInfo(kernel, &gEfiFileInfoGuid, &FileInfoSize, (void**)&FileInfo);

		UINTN size = sizeof(header);
		kernel->Read(kernel, &size, &header);
	}

	if (memcmp(&header.e_ident[EI_MAG0], ELFMAG, SELFMAG) != 0 ||
		header.e_ident[EI_CLASS] != ELFCLASS64 ||
		header.e_ident[EI_DATA] != ELFDATA2LSB ||
		header.e_type != ET_EXEC ||
		header.e_machine != EM_X86_64 ||
		header.e_version != EV_CURRENT) {
			Print(L"Kernel format is bad \n\r");
		}
		else {
			Print(L"Kernel header successfully verified \n\r");
		}

	Elf64_Phdr* phdrs;
	{
		kernel->SetPosition(kernel, header.e_phoff);
		UINTN size = header.e_phnum * header.e_phentsize;
		SystemTable->BootServices->AllocatePool(EfiLoaderData, size, (void**)&phdrs);
		kernel->Read(kernel, &size, phdrs);
	}

	for (
		Elf64_Phdr* phdr = phdrs; 
		(char*)phdr < (char*)phdrs + header.e_phnum * header.e_phentsize; 
		phdr = (Elf64_Phdr*)((char*)phdr + header.e_phentsize))
	{
		switch (phdr->p_type)
		{
			case PT_LOAD:
			{
				int pages = (phdr->p_memsz + 0x1000 -1) / 0x1000;
				Elf64_Addr segment = phdr->p_paddr;
				SystemTable->BootServices->AllocatePages(AllocateAddress, EfiLoaderData, pages, &segment);

				kernel->SetPosition(kernel, phdr->p_offset);
				UINTN size = phdr->p_filesz;
				kernel->Read(kernel, &size, (void*)segment);
				break;
			}
		}
	}

	Print(L"Kernel Loaded \r\n");

	PSF1_FONT* newFont = LoadPSF1Font(NULL, L"zap-light16.psf", ImageHandle, SystemTable);

	if (newFont == NULL) {
		Print(L"Font is not valid or was not found");
	} else {
		Print(L"Font found. char size: %d\n\r", newFont->psf1_header->charsize);
	}

	FrameBuffer* buffer = InitializeGOP();
	Print(L"Base: 0x%x\n\rSize: 0x%x\n\rWidth: %d\n\rHeight: %d\n\rPixelsPerScanLine %d\n\r",
		buffer->BaseAddress,
		buffer->BufferSize,
		buffer->Width,
		buffer->Height,
		buffer->PixelsPerScanLine);

	EFI_MEMORY_DESCRIPTOR* map = NULL;
	UINTN mapSize, mapKey;
	UINTN descriptorSize;
	UINT32 descriptorVersion;

	SystemTable->BootServices->GetMemoryMap(&mapSize, map, &mapKey, &descriptorSize, &descriptorVersion);
	SystemTable->BootServices->AllocatePool(EfiLoaderData, mapSize, (void**)&map);
	SystemTable->BootServices->GetMemoryMap(&mapSize, map, &mapKey, &descriptorSize, &descriptorVersion);

	EFI_CONFIGURATION_TABLE* configTable = SystemTable->ConfigurationTable;
	void* rsdp = NULL;
	EFI_GUID Acpi2TableGuid = ACPI_20_TABLE_GUID;
	for (UINTN index = 0; index < SystemTable->NumberOfTableEntries; index++){
		if (CompareGuid(&configTable[index].VendorGuid, &Acpi2TableGuid)){
			if (strcmp((CHAR8*)"RSD PTR ", (CHAR8*)configTable->VendorTable, 8)){
				rsdp = (void*)configTable->VendorTable;
			}
		}
		configTable++;
	}

	void (*kernelStart)(BootInfo*) = ((__attribute__((sysv_abi)) void (*)(BootInfo*) ) header.e_entry);

	BootInfo bootInfo;
	bootInfo.frameBuffer = &frameBuffer;
	bootInfo.psf1_Font = newFont;
	bootInfo.memMap = map;
	bootInfo.memMapSize = mapSize;
	bootInfo.memDescriptorSize = descriptorSize;
	bootInfo.rsdp = rsdp;

	SystemTable->BootServices->ExitBootServices(ImageHandle, mapKey);

	kernelStart(&bootInfo);

	return EFI_SUCCESS; // Exit the UEFI application
}
