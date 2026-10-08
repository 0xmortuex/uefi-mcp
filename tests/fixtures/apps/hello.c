/* Minimal UEFI application for uefi-mcp's tests: prints to ConOut, returns.
 * Self-contained (no EDK2/gnu-efi headers) so it builds with plain zig cc.
 * build.py compiles variants of it with -D flags. */
typedef unsigned long long UINTN;
typedef unsigned long long EFI_STATUS;
typedef unsigned short CHAR16;
typedef void *EFI_HANDLE;

typedef struct { unsigned long long Signature; unsigned int Revision, HeaderSize, CRC32, Reserved; } EFI_TABLE_HEADER;
struct SIMPLE_TEXT_OUTPUT;
typedef EFI_STATUS (__attribute__((ms_abi)) *TEXT_STRING)(struct SIMPLE_TEXT_OUTPUT *, CHAR16 *);
typedef struct SIMPLE_TEXT_OUTPUT { void *Reset; TEXT_STRING OutputString; } SIMPLE_TEXT_OUTPUT;
typedef struct {
    EFI_TABLE_HEADER Hdr;
    CHAR16 *FirmwareVendor;
    unsigned int FirmwareRevision;
    EFI_HANDLE ConsoleInHandle;
    void *ConIn;
    EFI_HANDLE ConsoleOutHandle;
    SIMPLE_TEXT_OUTPUT *ConOut;
} EFI_SYSTEM_TABLE;

#ifndef EXIT_STATUS
#define EXIT_STATUS 0
#endif

static void __attribute__((ms_abi, noinline)) say(EFI_SYSTEM_TABLE *st, CHAR16 *msg) {
    st->ConOut->OutputString(st->ConOut, msg);
}

/* FPTR_TABLE: call through a table of absolute function pointers. That needs
 * base relocations if the firmware loads the image anywhere other than its
 * preferred ImageBase - which OVMF always does. `volatile` stops the compiler
 * from folding the table into a direct call. */
#ifdef FPTR_TABLE
static void (__attribute__((ms_abi)) *volatile table[])(EFI_SYSTEM_TABLE *, CHAR16 *) = { say };
#endif

EFI_STATUS __attribute__((ms_abi)) EfiMain(EFI_HANDLE image, EFI_SYSTEM_TABLE *st) {
    (void)image;
#ifdef FPTR_TABLE
    table[0](st, (CHAR16 *)L"uefi-mcp hello: called through a function table\r\n");
#else
    say(st, (CHAR16 *)L"uefi-mcp hello: booted\r\n");
#endif
#ifdef CRASH
    __asm__ volatile("ud2");    /* #UD: OVMF's exception handler dumps state */
#endif
    return EXIT_STATUS;
}
