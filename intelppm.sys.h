typedef unsigned char   undefined;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef long long    longlong;
typedef unsigned long long    qword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef short    wchar_t;
typedef unsigned short    word;
#define unkbyte9   unsigned long long
#define unkbyte10   unsigned long long
#define unkbyte11   unsigned long long
#define unkbyte12   unsigned long long
#define unkbyte13   unsigned long long
#define unkbyte14   unsigned long long
#define unkbyte15   unsigned long long
#define unkbyte16   unsigned long long

#define unkuint9   unsigned long long
#define unkuint10   unsigned long long
#define unkuint11   unsigned long long
#define unkuint12   unsigned long long
#define unkuint13   unsigned long long
#define unkuint14   unsigned long long
#define unkuint15   unsigned long long
#define unkuint16   unsigned long long

#define unkint9   long long
#define unkint10   long long
#define unkint11   long long
#define unkint12   long long
#define unkint13   long long
#define unkint14   long long
#define unkint15   long long
#define unkint16   long long

#define unkfloat1   float
#define unkfloat2   float
#define unkfloat3   float
#define unkfloat5   double
#define unkfloat6   double
#define unkfloat7   double
#define unkfloat9   long double
#define unkfloat11   long double
#define unkfloat12   long double
#define unkfloat13   long double
#define unkfloat14   long double
#define unkfloat15   long double
#define unkfloat16   long double

#define BADSPACEBASE   void
#define code   void

typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
};

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY _IMAGE_RUNTIME_FUNCTION_ENTRY, *P_IMAGE_RUNTIME_FUNCTION_ENTRY;

struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
    ImageBaseOffset32 BeginAddress;
    ImageBaseOffset32 EndAddress;
    ImageBaseOffset32 UnwindInfoAddressOrData;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef ulong DWORD;

typedef uchar BYTE;

typedef ushort WORD;

typedef struct Var Var, *PVar;

struct Var {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

typedef struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY IMAGE_LOAD_CONFIG_CODE_INTEGRITY, *PIMAGE_LOAD_CONFIG_CODE_INTEGRITY;

struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY {
    word Flags;
    word Catalog;
    dword CatalogOffset;
    dword Reserved;
};

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 34404
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY64 IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;

typedef enum IMAGE_GUARD_FLAGS {
    IMAGE_GUARD_CF_INSTRUMENTED=256,
    IMAGE_GUARD_CFW_INSTRUMENTED=512,
    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT=1024,
    IMAGE_GUARD_SECURITY_COOKIE_UNUSED=2048,
    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT=4096,
    IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION=8192,
    IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT=16384,
    IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION=32768,
    IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT=65536,
    IMAGE_GUARD_RF_INSTRUMENTED=131072,
    IMAGE_GUARD_RF_ENABLE=262144,
    IMAGE_GUARD_RF_STRICT=524288,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_1=268435456,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_2=536870912,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_4=1073741824,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_8=2147483648
} IMAGE_GUARD_FLAGS;

struct IMAGE_LOAD_CONFIG_DIRECTORY64 {
    dword Size;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword GlobalFlagsClear;
    dword GlobalFlagsSet;
    dword CriticalSectionDefaultTimeout;
    qword DeCommitFreeBlockThreshold;
    qword DeCommitTotalFreeThreshold;
    pointer64 LockPrefixTable;
    qword MaximumAllocationSize;
    qword VirtualMemoryThreshold;
    qword ProcessAffinityMask;
    dword ProcessHeapFlags;
    word CsdVersion;
    word DependentLoadFlags;
    pointer64 EditList;
    pointer64 SecurityCookie;
    pointer64 SEHandlerTable;
    qword SEHandlerCount;
    pointer64 GuardCFCCheckFunctionPointer;
    pointer64 GuardCFDispatchFunctionPointer;
    pointer64 GuardCFFunctionTable;
    qword GuardCFFunctionCount;
    enum IMAGE_GUARD_FLAGS GuardFlags;
    struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
    pointer64 GuardAddressTakenIatEntryTable;
    qword GuardAddressTakenIatEntryCount;
    pointer64 GuardLongJumpTargetTable;
    qword GuardLongJumpTargetCount;
    pointer64 DynamicValueRelocTable;
    pointer64 CHPEMetadataPointer;
    pointer64 GuardRFFailureRoutine;
    pointer64 GuardRFFailureRoutineFunctionPointer;
    dword DynamicValueRelocTableOffset;
    word DynamicValueRelocTableSection;
    word Reserved1;
    pointer64 GuardRFVerifyStackPointerFunctionPointer;
    dword HotPatchTableOffset;
    dword Reserved2;
    qword Reserved3;
};

typedef struct StringFileInfo StringFileInfo, *PStringFileInfo;

struct StringFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER64 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    pointer64 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    qword SizeOfStackReserve;
    qword SizeOfStackCommit;
    qword SizeOfHeapReserve;
    qword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct StringTable StringTable, *PStringTable;

struct StringTable {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

struct IMAGE_NT_HEADERS64 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

typedef struct VS_VERSION_INFO VS_VERSION_INFO, *PVS_VERSION_INFO;

struct VS_VERSION_INFO {
    word StructLength;
    word ValueLength;
    word StructType;
    wchar16 Info[16];
    byte Padding[2];
    dword Signature;
    word StructVersion[2];
    word FileVersion[4];
    word ProductVersion[4];
    dword FileFlagsMask[2];
    dword FileFlags;
    dword FileOS;
    dword FileType;
    dword FileSubtype;
    dword FileTimestamp;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct VarFileInfo VarFileInfo, *PVarFileInfo;

struct VarFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
};

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct GuardCfgTableEntry GuardCfgTableEntry, *PGuardCfgTableEntry;

struct GuardCfgTableEntry {
    ImageBaseOffset32 Offset;
};

typedef struct _M128A _M128A, *P_M128A;

typedef struct _M128A M128A;

typedef ulonglong ULONGLONG;

typedef longlong LONGLONG;

struct _M128A {
    ULONGLONG Low;
    LONGLONG High;
};

typedef void *PVOID;

typedef struct _XSAVE_FORMAT _XSAVE_FORMAT, *P_XSAVE_FORMAT;

typedef struct _XSAVE_FORMAT XSAVE_FORMAT;

struct _XSAVE_FORMAT {
    WORD ControlWord;
    WORD StatusWord;
    BYTE TagWord;
    BYTE Reserved1;
    WORD ErrorOpcode;
    DWORD ErrorOffset;
    WORD ErrorSelector;
    WORD Reserved2;
    DWORD DataOffset;
    WORD DataSelector;
    WORD Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    M128A FloatRegisters[8];
    M128A XmmRegisters[16];
    BYTE Reserved4[96];
};

typedef union _union_54 _union_54, *P_union_54;

typedef XSAVE_FORMAT XMM_SAVE_AREA32;

typedef struct _struct_55 _struct_55, *P_struct_55;

struct _struct_55 {
    M128A Header[2];
    M128A Legacy[8];
    M128A Xmm0;
    M128A Xmm1;
    M128A Xmm2;
    M128A Xmm3;
    M128A Xmm4;
    M128A Xmm5;
    M128A Xmm6;
    M128A Xmm7;
    M128A Xmm8;
    M128A Xmm9;
    M128A Xmm10;
    M128A Xmm11;
    M128A Xmm12;
    M128A Xmm13;
    M128A Xmm14;
    M128A Xmm15;
};

union _union_54 {
    XMM_SAVE_AREA32 FltSave;
    struct _struct_55 s;
};

typedef char *va_list;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef struct _DISPATCHER_CONTEXT _DISPATCHER_CONTEXT, *P_DISPATCHER_CONTEXT;

struct _DISPATCHER_CONTEXT {
};

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef ulonglong DWORD64;

struct _CONTEXT {
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD ContextFlags;
    DWORD MxCsr;
    WORD SegCs;
    WORD SegDs;
    WORD SegEs;
    WORD SegFs;
    WORD SegGs;
    WORD SegSs;
    DWORD EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 Rip;
    union _union_54 u;
    M128A VectorRegister[26];
    DWORD64 VectorControl;
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
};

typedef enum _EXCEPTION_DISPOSITION {
    ExceptionContinueExecution=0,
    ExceptionContinueSearch=1,
    ExceptionNestedException=2,
    ExceptionCollidedUnwind=3
} _EXCEPTION_DISPOSITION;

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef ulonglong ULONG_PTR;

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

typedef enum _EXCEPTION_DISPOSITION EXCEPTION_DISPOSITION;

typedef ulonglong size_t;

typedef int errno_t;

typedef size_t rsize_t;

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
    char pdbpath[12];
};




undefined1 _tlgKeywordOn(longlong param_1,ulonglong param_2);
void FUN_1c0001034(longlong param_1,byte *param_2,undefined8 param_3,undefined8 param_4,undefined4 param_5,undefined8 *param_6);
ulonglong FUN_1c00010e0(longlong param_1,longlong param_2,undefined4 *param_3,longlong param_4);
ulonglong FUN_1c00011d0(longlong param_1,ulonglong *param_2,longlong param_3);
void FUN_1c0001280(longlong param_1,longlong param_2);
ulonglong FUN_1c0001400(longlong param_1,ulonglong *param_2);
void FUN_1c00015a0(longlong *param_1,longlong param_2);
ulonglong FUN_1c0001830(ulonglong *param_1,undefined4 param_2,int param_3,byte param_4);
void FUN_1c0001880(longlong param_1,longlong *param_2,char param_3,char param_4);
undefined8 FUN_1c0001bc0(byte *param_1,uint param_2,longlong param_3);
void FUN_1c0001c58(byte *param_1,ulonglong *param_2);
ulonglong * FUN_1c0001ce0(byte *param_1,ulonglong *param_2);
ulonglong FUN_1c0001df4(char *param_1);
ulonglong FUN_1c0001ee0(char *param_1);
void FUN_1c0001f48(byte *param_1,ulonglong param_2);
ulonglong FUN_1c0001fc0(byte *param_1,ulonglong param_2);
ulonglong FUN_1c0002030(longlong param_1,uint param_2,uint param_3,uint param_4);
ulonglong FUN_1c00020b0(longlong param_1,uint param_2);
void FUN_1c0002120(longlong param_1,undefined8 param_2,ulonglong *param_3,ulonglong *param_4);
undefined8 FUN_1c0002390(longlong param_1,ulonglong *param_2,longlong param_3);
void FUN_1c0002504(longlong param_1,char *param_2);
ulonglong FUN_1c0002530(char *param_1);
void FUN_1c0002630(longlong param_1);
void FUN_1c0002654(longlong param_1,ulonglong param_2,char param_3);
void FUN_1c0002860(longlong param_1,int param_2,ulonglong param_3);
ulonglong FUN_1c00028b0(char *param_1);
void FUN_1c0002960(ulonglong *param_1,char param_2,ulonglong *param_3,ulonglong *param_4);
void FUN_1c0002c40(undefined8 *param_1,undefined8 *param_2,byte param_3);
void FUN_1c0002cb0(longlong param_1,ulonglong *param_2,char param_3,char param_4);
undefined8 FUN_1c0002df0(undefined8 param_1,undefined2 param_2,undefined8 param_3,byte param_4);
undefined8 FUN_1c0002ef0(undefined8 param_1,undefined2 param_2);
void FUN_1c0002fb0(undefined8 *param_1);
void FUN_1c0002fd0(undefined4 *param_1,char param_2,longlong *param_3,longlong *param_4);
undefined1 FUN_1c0003090(longlong param_1,uint param_2,uint param_3,uint param_4,uint param_5,undefined8 param_6,undefined8 param_7,uint param_8,undefined4 *param_9,ulonglong *param_10,undefined8 *param_11);
uint FUN_1c0003250(undefined8 param_1,uint param_2);
uint FUN_1c0003260(longlong param_1,uint param_2,uint param_3,uint param_4,int param_5,uint param_6,int param_7,byte param_8,undefined4 *param_9,ulonglong *param_10,longlong *param_11);
undefined8 FUN_1c00035c0(undefined8 param_1,char param_2,undefined8 *param_3,undefined8 *param_4);
void FUN_1c0003610(undefined8 param_1,undefined8 param_2);
void FUN_1c0003690(uint param_1,longlong param_2,undefined8 param_3,uint param_4,ulonglong *param_5);
void FUN_1c0003780(undefined4 param_1,undefined8 param_2);
ulonglong FUN_1c0003830(undefined8 param_1,uint param_2);
void FUN_1c0003880(int param_1);
void FUN_1c00039c0(uint param_1);
longlong FUN_1c00039f0(longlong param_1,int param_2);
ulonglong FUN_1c0003a1c(uint *param_1,longlong param_2);
void FUN_1c0003a50(undefined8 *param_1,uint param_2,int param_3,undefined4 param_4,undefined8 param_5);
void FUN_1c0003a90(undefined8 param_1,undefined8 param_2);
void FUN_1c0003c10(undefined8 *param_1,int param_2);
void FUN_1c0003db4(undefined8 param_1,byte param_2,uint param_3,undefined2 param_4,undefined8 param_5);
undefined8 FUN_1c0003ee0(longlong param_1,undefined8 param_2,undefined8 param_3,undefined4 *param_4,undefined8 *param_5);
void FUN_1c0003f70(longlong param_1,undefined4 param_2);
void FUN_1c0003fa8(longlong param_1,longlong param_2,longlong param_3,int param_4,longlong param_5);
undefined8 FUN_1c00040c0(longlong param_1,undefined8 param_2,uint param_3,undefined8 param_4,undefined4 param_5);
void FUN_1c00040f4(undefined8 param_1,byte param_2,uint param_3,undefined2 param_4,undefined8 param_5,undefined *param_6);
void FUN_1c0004258(undefined8 param_1,byte param_2,uint param_3,undefined2 param_4,undefined8 param_5);
ulonglong FUN_1c0004330(longlong param_1,ulonglong *param_2,undefined8 param_3,char param_4);
ulonglong FUN_1c00043a0(longlong param_1,ulonglong *param_2,char param_3,char param_4);
void FUN_1c0004500(undefined8 *param_1,uint *param_2);
void FUN_1c0004570(longlong param_1,int param_2);
void FUN_1c00047f8(longlong *param_1,int param_2);
undefined4 FUN_1c0004970(undefined8 *param_1,undefined8 param_2);
void FUN_1c0004a18(undefined8 param_1,byte param_2,uint param_3,undefined2 param_4,undefined8 param_5);
int FUN_1c0004b40(uint param_1,int *param_2,longlong param_3);
undefined8 FUN_1c0004c70(longlong *param_1,int param_2);
undefined8 FUN_1c0004d10(longlong param_1);
ulonglong FUN_1c0004d50(undefined8 *param_1,undefined8 param_2,uint param_3,undefined4 param_4,undefined4 param_5,undefined4 param_6,undefined8 param_7);
void FUN_1c0004dd8(undefined8 param_1,undefined4 *param_2);
void FUN_1c0004e60(undefined8 param_1);
void FUN_1c0004e90(undefined8 param_1);
void FUN_1c0004ecc(undefined *param_1,undefined8 param_2,undefined1 param_3);
undefined4 FUN_1c0004f80(undefined8 param_1,longlong param_2,int *param_3,undefined4 *param_4);
void FUN_1c0005060(longlong param_1,char param_2,undefined8 *param_3,undefined8 *param_4);
undefined8 FUN_1c00050d8(longlong *param_1,longlong *param_2);
void FUN_1c000512c(void);
undefined8 FUN_1c0005190(void);
void FUN_1c0005268(longlong param_1);
void FUN_1c0005290(undefined8 param_1,longlong param_2);
void _guard_check_icall(void);
void FUN_1c0005360(undefined8 param_1,longlong param_2);
void FUN_1c000537c(int *param_1);
void FUN_1c00053d0(longlong param_1,undefined8 param_2);
void FUN_1c0005420(longlong param_1,undefined8 param_2);
void FUN_1c0005648(undefined8 param_1,byte param_2,uint param_3,undefined2 param_4,undefined8 param_5);
void FUN_1c0005750(undefined8 param_1,undefined8 *param_2);
void FUN_1c0005780(undefined8 *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 FUN_1c0005840(undefined8 param_1);
void FUN_1c000591c(undefined8 *param_1);
longlong FUN_1c0005940(longlong *param_1,int param_2);
void FUN_1c0005a24(undefined8 param_1,undefined4 param_2,undefined8 *param_3);
void FUN_1c0005a40(longlong param_1,undefined8 param_2);
void FUN_1c0005a8c(undefined4 param_1,uint *param_2);
void FUN_1c0005be0(void);
void FUN_1c0005c70(longlong param_1,char param_2,char param_3);
void FUN_1c0005ce0(void);
undefined4 FUN_1c0005fd8(void);
ulonglong FUN_1c00061c0(longlong param_1,longlong *param_2,uint *param_3,ulonglong param_4,undefined8 *param_5,ulonglong param_6,undefined8 *param_7);
void FUN_1c00063b0(undefined8 param_1,byte param_2,uint param_3,undefined2 param_4,undefined8 param_5);
undefined8 FUN_1c00064ac(char *param_1);
uint FUN_1c00064c4(ulonglong param_1,int param_2,undefined8 *param_3);
undefined8 FUN_1c0006560(longlong param_1);
int FUN_1c0006588(longlong param_1);
undefined8 FUN_1c0006730(longlong param_1);
void FUN_1c00067e4(undefined8 *param_1);
void FUN_1c0006824(void);
void FUN_1c0006880(undefined8 param_1,longlong param_2);
undefined8 FUN_1c00068c0(undefined8 param_1,undefined8 param_2);
undefined4 FUN_1c00068d8(wchar_t *param_1,longlong param_2,wchar_t *param_3,undefined8 param_4);
void FUN_1c0006954(void);
void FUN_1c00069c0(void);
void FUN_1c0006a34(void);
ulonglong FUN_1c0006aa8(undefined8 param_1,char *param_2);
void FUN_1c0006adc(void);
void FUN_1c0006b44(void);
undefined8 FUN_1c0006b90(uint param_1);
ulonglong FUN_1c0006ba8(undefined8 param_1,char *param_2);
void FUN_1c0006c0c(longlong param_1);
uint FUN_1c0006c60(short *param_1,longlong param_2,undefined8 param_3,longlong param_4);
void FUN_1c0006cbc(undefined8 *param_1);
int * FUN_1c0006cd0(int param_1);
void FUN_1c0006d20(void);
void FUN_1c0006d30(void);
EXCEPTION_DISPOSITION __C_specific_handler(_EXCEPTION_RECORD *ExceptionRecord,void *EstablisherFrame,_CONTEXT *ContextRecord,_DISPATCHER_CONTEXT *DispatcherContext);
errno_t __cdecl memcpy_s(void *_Dst,rsize_t _DstSize,void *_Src,rsize_t _MaxCount);
undefined8 FUN_1c0006e00(void);
void FUN_1c0006ec8(void);
void FUN_1c0006f40(int param_1,ulonglong param_2,ulonglong param_3,uint param_4,ulonglong *param_5);
void FUN_1c000762c(void);
void FUN_1c00076a0(uint param_1,char param_2,char param_3);
ulonglong FUN_1c00077b0(void);
ulonglong FUN_1c00077d4(void);
void FUN_1c000780c(ulonglong param_1,int param_2);
undefined8 FUN_1c0007830(longlong param_1,undefined8 *param_2);
bool FUN_1c000788c(void);
ulonglong FUN_1c00078a0(void);
void FUN_1c00078c0(longlong *param_1,undefined8 param_2,char param_3,char param_4);
void FUN_1c0007980(longlong *param_1,ulonglong *param_2,char param_3,char param_4);
void FUN_1c0007a60(longlong *param_1,ulonglong *param_2,char param_3,char param_4);
void FUN_1c0007ab0(longlong param_1,ulonglong *param_2,char param_3,char param_4);
void FUN_1c0007bb0(longlong *param_1,undefined8 param_2,char param_3,char param_4);
void FUN_1c0007c10(void);
undefined8 FUN_1c0007c80(undefined8 param_1,undefined8 param_2,undefined8 param_3);
undefined8 FUN_1c0007cb0(ulonglong param_1,undefined8 param_2,ushort param_3,undefined8 param_4,byte param_5);
undefined8 FUN_1c0007d60(ulonglong param_1,undefined8 param_2,undefined2 param_3);
void FUN_1c0007dc8(uint *param_1,uint param_2,uint param_3,uint *param_4);
void FUN_1c0007eac(uint *param_1,uint param_2,uint param_3,uint *param_4);
uint * FUN_1c0007f9c(uint *param_1,uint *param_2,uint param_3,uint param_4,uint param_5);
void FUN_1c0008124(longlong param_1,undefined8 param_2,int param_3,undefined8 param_4);
void FUN_1c00081b4(longlong param_1,undefined8 param_2,uint param_3,uint param_4);
ulonglong FUN_1c000829c(uint *param_1,ulonglong param_2,longlong param_3);
void FUN_1c00083ac(uint param_1,int param_2,undefined8 *param_3);
uint FUN_1c0008404(longlong param_1,undefined4 *param_2);
uint FUN_1c0008540(int param_1,int param_2);
void FUN_1c00085e0(undefined8 *param_1,undefined4 param_2,undefined8 *param_3);
uint FUN_1c0008600(uint *param_1,uint param_2);
undefined8 FUN_1c0008650(longlong param_1);
void FUN_1c00086cc(void);
void entry(longlong param_1,undefined8 param_2);
int FUN_1c0008744(longlong param_1,undefined8 param_2);
void FUN_1c00088d0(void);
int FUN_1c0008904(void);
void FUN_1c0008a64(void);
longlong * FUN_1c0008b20(longlong *param_1,longlong *param_2);
undefined8 FUN_1c0008b68(void);
void FUN_1c0008c30(longlong param_1,undefined4 param_2,undefined8 param_3);
void FUN_1c0008d44(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined8 * FUN_1c0008dc4(int param_1);
undefined8 * FUN_1c0008df0(int param_1);
void FUN_1c0008e1c(undefined8 param_1,undefined8 *param_2);
uint FUN_1c0008e34(longlong param_1);
undefined8 FUN_1c0008e78(undefined8 param_1,char *param_2);
void FUN_1c0008f08(uint param_1,char *param_2,ulonglong param_3);
void FUN_1c0008fa8(uint param_1,byte *param_2,ulonglong *param_3);
void FUN_1c0008fdc(longlong param_1,byte *param_2,ulonglong *param_3);
void FUN_1c000900c(undefined8 param_1,char *param_2,ulonglong param_3,undefined4 param_4);
void FUN_1c00090a0(undefined8 param_1,byte param_2,undefined8 *param_3,longlong param_4);
longlong * FUN_1c00090fc(longlong *param_1);
void FUN_1c0009130(undefined4 param_1);
uint * FUN_1c00091b4(uint *param_1);
void FUN_1c0009210(undefined8 param_1);
void FUN_1c0009250(undefined8 param_1,longlong param_2);
void FUN_1c00092a0(longlong *param_1);
void FUN_1c0009320(longlong *param_1,ulonglong param_2);
void FUN_1c0009370(longlong *param_1,int param_2);
void FUN_1c00093a0(longlong *param_1,uint param_2);
void FUN_1c00093d0(longlong param_1,undefined8 param_2);
void FUN_1c0009414(longlong param_1,uint *param_2);
void FUN_1c00094a8(longlong param_1,undefined8 *param_2,undefined4 *param_3);
void FUN_1c0009510(longlong *param_1,longlong *param_2,char param_3,char param_4);
void FUN_1c0009640(longlong param_1,ulonglong *param_2,char param_3,char param_4);
void FUN_1c00098d0(longlong *param_1,longlong *param_2,char param_3,char param_4);
undefined8 FUN_1c0009b20(longlong param_1,uint param_2,longlong *param_3);
void FUN_1c0009b58(undefined8 param_1,byte param_2,uint param_3,undefined2 param_4,undefined8 param_5,wchar_t *param_6);
void FUN_1c0009cbc(undefined8 param_1,byte param_2,uint param_3,undefined2 param_4,undefined8 param_5,undefined *param_6);
undefined8 FUN_1c0009e44(char *param_1,longlong param_2,char *param_3,undefined8 param_4);
void FUN_1c0009eb8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined2 param_4,undefined8 param_5,wchar_t *param_6);
void FUN_1c000a00c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined2 param_4,undefined8 param_5,wchar_t *param_6);
void FUN_1c000a188(undefined8 param_1);
void FUN_1c000a328(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined2 param_4,undefined8 param_5,wchar_t *param_6,wchar_t *param_7);
void FUN_1c000a4c0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined2 param_4,undefined8 param_5,wchar_t *param_6,wchar_t *param_7);
void FUN_1c000a684(undefined8 param_1);
void FUN_1c000a8cc(undefined8 param_1);
void FUN_1c000aad8(undefined8 param_1);
void FUN_1c000aca4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined2 param_4,undefined8 param_5,wchar_t *param_6,wchar_t *param_7);
void FUN_1c000ae90(undefined8 param_1);
void FUN_1c000b0a4(undefined8 param_1);
void FUN_1c000b290(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined2 param_4,undefined8 param_5,wchar_t *param_6,wchar_t *param_7,undefined *param_8);
void FUN_1c000b4ac(undefined8 param_1);
void FUN_1c000b728(undefined8 param_1);
void FUN_1c000b9d4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined2 param_4,undefined8 param_5,wchar_t *param_6,undefined *param_7);
void FUN_1c000bb74(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined2 param_4,undefined8 param_5,wchar_t *param_6,undefined *param_7);
void FUN_1c000bd40(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined2 param_4);
void FUN_1c000be30(undefined8 *param_1);
undefined8 FUN_1c000bf74(longlong param_1);
ulonglong FUN_1c000bf80(undefined8 param_1,uint param_2,longlong *param_3,uint *param_4);
undefined8 FUN_1c000c0e0(undefined8 param_1,uint param_2,undefined2 *param_3,uint *param_4);
undefined4 FUN_1c000c2c0(undefined8 param_1,uint param_2,undefined4 *param_3,uint *param_4);
undefined8 FUN_1c000c490(undefined8 param_1,uint param_2,undefined1 *param_3,uint *param_4);
longlong FUN_1c000c684(ushort *param_1,short *param_2);
void FUN_1c000c740(undefined8 param_1);
void FUN_1c000c898(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined2 param_4,undefined8 param_5,undefined8 param_6,undefined *param_7);
void FUN_1c000c9dc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined2 param_4);
void FUN_1c000ca88(undefined8 param_1);
void FUN_1c000cc3c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined2 param_4,undefined8 param_5,undefined *param_6);
void FUN_1c000cd80(undefined8 param_1);
void FUN_1c000cec8(undefined8 param_1);
void FUN_1c000d050(undefined8 param_1);
void FUN_1c000d250(undefined8 param_1,undefined8 *param_2);
undefined8 FUN_1c000d280(int param_1,undefined8 param_2,char param_3);
void FUN_1c000d2c0(undefined8 param_1);
void FUN_1c000d4c8(undefined8 param_1);
void FUN_1c000d5f8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined2 param_4);
undefined4 FUN_1c000d6b0(longlong param_1,ulonglong param_2);
undefined1 FUN_1c000d6f0(void);
undefined4 FUN_1c000d700(longlong param_1,longlong *param_2);
ulonglong FUN_1c000d780(char *param_1,uint param_2);
ulonglong FUN_1c000d840(char *param_1,uint param_2);
undefined8 FUN_1c000d920(void);
void FUN_1c000d9a0(undefined8 *param_1,undefined8 param_2,undefined8 *param_3);
void FUN_1c000d9c0(ulonglong *param_1,ulonglong param_2,ulonglong *param_3);
void FUN_1c000da00(undefined4 *param_1);
ulonglong FUN_1c000da50(char *param_1,uint param_2);
undefined8 FUN_1c000daa0(longlong param_1,ulonglong param_2);
void FUN_1c000db00(undefined8 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined8 param_5);
ulonglong FUN_1c000db80(undefined8 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined8 param_5);
void FUN_1c000dbe0(undefined8 *param_1,uint param_2,int param_3,undefined4 param_4,undefined8 param_5);
uint FUN_1c000dc20(longlong param_1,longlong *param_2);
void FUN_1c000dc80(undefined8 *param_1,uint param_2,int param_3);
undefined8 FUN_1c000dd30(undefined8 *param_1,undefined8 param_2,int param_3);
undefined1 FUN_1c000dd60(undefined8 *param_1);
undefined1 FUN_1c000ddd0(undefined8 *param_1);
void FUN_1c000de40(undefined8 *param_1,undefined8 param_2,int param_3,uint param_4,uint *param_5);
ulonglong FUN_1c000dec0(undefined8 *param_1,undefined8 param_2,int param_3,uint param_4,uint *param_5);
void FUN_1c000df44(longlong param_1,undefined4 *param_2);
undefined8 FUN_1c000dfec(longlong param_1,uint *param_2);
undefined8 FUN_1c000e110(undefined8 param_1,uint *param_2);
longlong * FUN_1c000e230(longlong param_1,undefined *param_2);
undefined8 FUN_1c000e5e8(longlong param_1);
void FUN_1c000e6e0(longlong param_1);
void FUN_1c000e6fc(longlong param_1,longlong *param_2);
void FUN_1c000e86c(undefined8 param_1,byte param_2,uint param_3,undefined2 param_4,undefined8 param_5);
void FUN_1c000e994(undefined8 param_1);
void FUN_1c000ea80(undefined8 param_1,longlong param_2,undefined8 *param_3,undefined4 param_4);
void FUN_1c000eac0(longlong *param_1,undefined8 param_2,char param_3,char param_4);
void FUN_1c000eba0(longlong *param_1,ulonglong *param_2,undefined8 param_3,char param_4);
void FUN_1c000ec70(longlong param_1,undefined4 *param_2);
undefined8 FUN_1c000ec80(longlong param_1,longlong param_2);
undefined8 FUN_1c000ed50(uint param_1,char *param_2,uint param_3,longlong param_4);
void FUN_1c000ee00(void);
undefined4 FUN_1c000ee20(void);
undefined4 FUN_1c000ee30(void);
uint FUN_1c000ee44(short *param_1,undefined8 param_2,longlong param_3);
void FUN_1c000eeb0(uint param_1);
void FUN_1c000eef4(ulonglong param_1,int param_2);
ulonglong FUN_1c000ef10(void);
void FUN_1c000ef50(longlong param_1,undefined8 param_2,undefined8 *param_3,undefined8 *param_4);
void FUN_1c000efd0(longlong param_1,undefined8 param_2,undefined8 *param_3,undefined8 *param_4);
void FUN_1c000f050(longlong param_1,undefined4 *param_2);
void FUN_1c000f0d0(longlong param_1,undefined4 *param_2);
int FUN_1c000f14c(undefined8 param_1,undefined8 param_2);
int FUN_1c000f1b8(longlong param_1,undefined4 *param_2,undefined4 *param_3);
void FUN_1c000f25c(undefined8 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,undefined4 param_6,undefined1 param_7);
void FUN_1c000f320(longlong param_1,undefined4 *param_2,char param_3,char param_4);
ulonglong FUN_1c000f3e0(longlong param_1,uint param_2,uint param_3,uint param_4);
void FUN_1c000f480(longlong param_1,undefined8 *param_2,char param_3,char param_4);
undefined4 FUN_1c000f530(longlong param_1,uint param_2,uint param_3,uint param_4,int param_5,undefined8 param_6,undefined8 param_7,uint param_8,uint *param_9,ulonglong *param_10,undefined8 *param_11);
ulonglong FUN_1c000f6b4(longlong param_1,int param_2);
void FUN_1c000f720(longlong param_1,undefined4 param_2);
void FUN_1c000f730(undefined1 param_1,undefined8 param_2,uint param_3,undefined8 param_4,longlong param_5,longlong param_6,undefined8 param_7,undefined8 param_8);
undefined8 FUN_1c000f9cc(longlong param_1,int param_2);
void FUN_1c000faa0(longlong param_1,undefined4 *param_2);
void FUN_1c000fab0(void);
void FUN_1c000fc50(undefined8 param_1,undefined *param_2);
void FUN_1c000fd00(undefined8 param_1,undefined *param_2);
void FUN_1c000fdb0(int param_1,undefined *param_2);
void FUN_1c000ff40(undefined *param_1);
void FUN_1c000ff90(longlong param_1,int *param_2,char param_3,char param_4);
void FUN_1c000ffb0(undefined *param_1);
uint FUN_1c0010000(undefined8 param_1,uint param_2,uint param_3,uint param_4);
void FUN_1c0010064(undefined8 param_1);
undefined8 FUN_1c0010140(longlong param_1,longlong param_2,ulonglong param_3,undefined8 param_4,undefined4 param_5,uint param_6,longlong param_7);
undefined8 __GSHandlerCheck(undefined8 param_1,ulonglong param_2,undefined8 param_3,longlong param_4);
void __GSHandlerCheckCommon(ulonglong param_1,longlong param_2,uint *param_3);
void __GSHandlerCheck_SEH(_EXCEPTION_RECORD *param_1,void *param_2,_CONTEXT *param_3,_DISPATCHER_CONTEXT *param_4);
void FUN_1c0010330(longlong param_1);
void FUN_1c0010360(void);
void FUN_1c0010370(int param_1,undefined4 *param_2);
void _guard_dispatch_icall(void);
void _guard_dispatch_icall(void);
void FUN_1c0010480(undefined8 *param_1,undefined8 *param_2,ulonglong param_3);
longlong * FUN_1c0010780(longlong *param_1,byte param_2,undefined1 *param_3);
undefined8 FUN_1c00108c0(undefined1 *param_1,undefined8 param_2,longlong param_3);
undefined8 FUN_1c0010940(void);
void FUN_1c0010b00(undefined1 *param_1,undefined8 param_2,longlong param_3);
ulonglong FUN_1c0027008(longlong param_1);
ulonglong FUN_1c0027238(undefined8 param_1);
undefined8 FUN_1c0027354(uint *param_1,wchar_t *param_2);
int FUN_1c0027424(longlong param_1,longlong *param_2);
int FUN_1c0027628(longlong param_1);
void FUN_1c00279b4(longlong param_1,int param_2,char *param_3);
void FUN_1c0027bb0(void);
ulonglong FUN_1c0027ce8(void);
int FUN_1c0027e00(longlong param_1,undefined8 *param_2);
undefined4 FUN_1c0027f04(uint *param_1,uint *param_2,undefined8 param_3);
byte FUN_1c00280b8(longlong param_1,longlong param_2,ulonglong *param_3);
void FUN_1c0028154(longlong param_1);
void FUN_1c002848c(longlong param_1);
void FUN_1c0028590(longlong param_1,int param_2);
void FUN_1c00285d0(byte *param_1,undefined *param_2);
int FUN_1c0028830(longlong param_1,longlong param_2);
void FUN_1c00288a8(undefined8 param_1,undefined8 param_2,undefined4 *param_3);
void FUN_1c00288cc(longlong param_1);
void FUN_1c0028980(longlong param_1);
int FUN_1c0028a34(undefined8 param_1,int param_2,undefined8 *param_3);
undefined8 * FUN_1c0028bfc(int param_1);
void FUN_1c0028c84(uint *param_1);
int FUN_1c0028f94(longlong param_1,undefined1 *param_2);
void FUN_1c0029060(longlong param_1,longlong param_2);
int FUN_1c002907c(longlong param_1);
undefined8 FUN_1c0029200(longlong param_1);
ulonglong FUN_1c0029250(longlong param_1);
void FUN_1c00293e0(undefined8 param_1,longlong param_2);
bool FUN_1c002953c(longlong param_1,uint *param_2);
void FUN_1c0029650(void);
void FUN_1c00296cc(void);
void FUN_1c0029744(undefined8 param_1,undefined8 *param_2);
undefined8 FUN_1c00298b0(int param_1);
void FUN_1c00298e0(longlong param_1,undefined8 param_2,longlong *param_3);
undefined4 * FUN_1c00299dc(longlong param_1,int param_2,int param_3);
void FUN_1c0029b20(longlong param_1);
void FUN_1c0029b60(void);
void FUN_1c0029ca4(longlong param_1);
void FUN_1c0029dcc(void);
void FUN_1c0029e3c(undefined8 param_1,undefined8 param_2,undefined8 param_3);
void FUN_1c0029f88(uint *param_1);
void FUN_1c002a224(longlong param_1);
void FUN_1c002a250(void);
void FUN_1c002a2bc(undefined8 param_1,undefined8 param_2);
undefined8 FUN_1c002a3a0(void);
void FUN_1c002a570(int param_1);
void FUN_1c002a630(void);
undefined4 FUN_1c002a72c(longlong param_1);
void FUN_1c002a7f0(uint *param_1);
void FUN_1c002a8f0(void);
void FUN_1c002a910(longlong param_1);
undefined * FUN_1c002ab60(longlong param_1);
void FUN_1c002abd0(longlong param_1,longlong param_2,undefined8 *param_3,undefined8 *param_4,ulonglong *param_5,undefined8 *param_6,undefined1 *param_7,undefined1 *param_8,undefined1 *param_9,int *param_10);
ulonglong FUN_1c002aff0(longlong param_1);
bool FUN_1c002b038(void);
void FUN_1c002b084(byte *param_1);
undefined8 FUN_1c002b190(char *param_1,undefined8 param_2,uint *param_3);
void FUN_1c002b1e8(uint *param_1,undefined4 param_2,int param_3);
void FUN_1c002b2c0(undefined1 *param_1);
void FUN_1c002b540(void);
void FUN_1c002b5c8(longlong param_1);
int FUN_1c002b690(longlong param_1);
void FUN_1c002b770(longlong param_1,int param_2,byte param_3);
ulonglong FUN_1c002b7d0(longlong param_1);
longlong FUN_1c002b920(longlong *param_1);
ulonglong FUN_1c002b9f0(void);
void FUN_1c002bcec(longlong param_1);
void FUN_1c002bf18(char param_1);
void FUN_1c002bf44(undefined8 param_1);
void FUN_1c002bf98(char param_1);
void FUN_1c002bfc4(longlong param_1,char param_2);
void FUN_1c002c0f4(longlong param_1,undefined4 param_2,undefined4 param_3);
void FUN_1c002c1ec(char param_1);
void FUN_1c002c218(char param_1);
void FUN_1c002c2e0(char param_1);
void FUN_1c002c30c(longlong param_1);
void FUN_1c002c3bc(undefined8 param_1,ulonglong param_2,ulonglong *param_3);
int FUN_1c002c480(undefined8 param_1);
undefined8 FUN_1c002c5d0(void);
undefined8 FUN_1c002c5e0(void);
int FUN_1c002c5f0(undefined8 param_1,undefined8 param_2);
void FUN_1c002c980(void);
void FUN_1c002c9dc(void);
void FUN_1c002ca34(undefined8 param_1);
undefined4 FUN_1c002caf0(byte param_1,undefined8 param_2,uint param_3,uint *param_4,longlong param_5,uint *param_6);
void FUN_1c002cd78(void);
void FUN_1c002cdd0(int param_1,longlong param_2,uint *param_3);
void FUN_1c002ce38(void);
uint FUN_1c002cef0(uint *param_1,longlong param_2);
uint FUN_1c002cf28(uint *param_1,uint param_2,longlong param_3);
void FUN_1c002d000(int param_1);
void FUN_1c002d060(void);
void FUN_1c002d07c(void);
void FUN_1c002d130(undefined8 *param_1);
uint FUN_1c002d2ac(longlong param_1,longlong param_2,longlong param_3,uint param_4,undefined1 *param_5);
ulonglong FUN_1c002d468(longlong param_1);
undefined1 FUN_1c002d874(char *param_1);
int FUN_1c002d8dc(char *param_1,uint *param_2,wchar_t *param_3,wchar_t *param_4);
undefined8 FUN_1c002d9e4(uint *param_1,wchar_t *param_2,undefined8 param_3);
undefined8 FUN_1c002db80(char *param_1,undefined8 param_2,undefined8 param_3,undefined *param_4,wchar_t *param_5);
ulonglong FUN_1c002dd78(char *param_1,uint *param_2,wchar_t *param_3,undefined4 *param_4);
undefined8 FUN_1c002def0(uint *param_1,char param_2,wchar_t *param_3);
void FUN_1c002e008(longlong param_1,uint param_2,uint param_3,uint param_4,longlong param_5);
undefined4 FUN_1c002e244(longlong param_1,uint param_2,undefined8 param_3,longlong param_4,undefined8 param_5,undefined1 *param_6);
undefined4 FUN_1c002e39c(undefined8 param_1,undefined8 param_2,longlong param_3,undefined8 param_4,undefined1 *param_5);
int FUN_1c002e490(undefined8 param_1,uint *param_2);
ulonglong FUN_1c002e594(uint *param_1,undefined8 param_2);
void FUN_1c002e624(longlong param_1,uint param_2);
void FUN_1c002e778(uint *param_1,wchar_t *param_2);
undefined8 FUN_1c002ea28(wchar_t *param_1,uint *param_2,wchar_t *param_3,uint *param_4);
undefined8 FUN_1c002ec2c(wchar_t *param_1,longlong param_2,wchar_t *param_3,longlong param_4);
ulonglong FUN_1c002ed60(longlong param_1,undefined8 param_2,wchar_t *param_3);
undefined8 FUN_1c002ee80(char *param_1);
ulonglong FUN_1c002ef50(char *param_1,wchar_t *param_2,undefined8 param_3);
undefined8 FUN_1c002f02c(int *param_1);
undefined8 FUN_1c002f120(wchar_t *param_1,char *param_2,wchar_t *param_3,longlong param_4,undefined *param_5);
ulonglong FUN_1c002f1e4(wchar_t *param_1,longlong param_2,wchar_t *param_3,longlong param_4);
ulonglong FUN_1c002f3cc(longlong param_1);
ulonglong FUN_1c002f784(longlong param_1,wchar_t *param_2);
undefined4 FUN_1c002f7e8(uint *param_1,undefined *param_2,undefined8 param_3);
undefined8 FUN_1c002f8d8(undefined8 param_1,uint *param_2,undefined8 param_3,uint *param_4);
bool FUN_1c002f9d8(char *param_1,undefined8 param_2);
undefined8 FUN_1c002fa14(wchar_t *param_1,uint *param_2,undefined8 param_3,uint *param_4);
int FUN_1c002fb00(char *param_1,uint *param_2,wchar_t *param_3,uint *param_4);
undefined8 FUN_1c002fbc4(char *param_1);
int FUN_1c002fca0(void);
int FUN_1c002fd40(void);
void FUN_1c002fdd8(longlong param_1,longlong *param_2);
int FUN_1c003055c(longlong param_1,void *param_2,ushort param_3);
void FUN_1c0030660(longlong param_1,int param_2,undefined8 *param_3);
void FUN_1c00309a8(longlong param_1,undefined8 *param_2);
void FUN_1c0030d50(longlong param_1,undefined8 *param_2);
void FUN_1c003105c(longlong param_1,undefined8 *param_2);
ulonglong FUN_1c0031444(longlong param_1,undefined8 *param_2);
void FUN_1c0031670(undefined8 param_1,longlong param_2);
undefined8 FUN_1c00316d0(longlong param_1,undefined8 param_2,uint param_3);
int FUN_1c0031750(longlong param_1,longlong *param_2,uint param_3);
void FUN_1c0031924(longlong param_1,longlong *param_2);
void FUN_1c0031ac0(longlong param_1,wchar_t *param_2,char param_3,undefined8 *param_4);
ulonglong FUN_1c003249c(int *param_1,ulonglong param_2,ushort *param_3);
undefined8 FUN_1c0032640(longlong param_1,undefined4 *param_2,uint param_3);
undefined8 FUN_1c0032730(longlong param_1,undefined2 *param_2,uint param_3);
undefined8 FUN_1c0032760(longlong param_1,undefined8 *param_2,uint param_3);
ulonglong FUN_1c00327f0(longlong param_1,longlong *param_2,uint param_3);
void FUN_1c0032960(longlong param_1,undefined8 param_2);
void FUN_1c0032ab8(char *param_1);
int FUN_1c0032b28(longlong param_1);
void FUN_1c0032bf4(undefined8 *param_1);
void FUN_1c0032db4(longlong param_1);
void FUN_1c0032ff8(longlong param_1,wchar_t *param_2,undefined8 param_3);
void FUN_1c003343c(byte *param_1,undefined *param_2);
void FUN_1c00335a8(uint *param_1,undefined8 param_2,undefined8 param_3);
void FUN_1c00338a0(uint *param_1,undefined *param_2);
char * FUN_1c0033b84(int param_1);
char * FUN_1c0033bd0(int param_1);
char * FUN_1c0033c40(short param_1);
undefined8 FUN_1c0033c90(longlong param_1);
int FUN_1c0033cd8(longlong param_1);
ulonglong FUN_1c0033ee4(longlong param_1);
ulonglong FUN_1c0034038(longlong param_1);
undefined1 FUN_1c003418c(longlong param_1);
undefined4 FUN_1c0034350(longlong param_1);
int FUN_1c00345f8(longlong param_1);
undefined4 FUN_1c0034798(longlong param_1,uint *param_2,uint *param_3,longlong param_4);
undefined8 FUN_1c0034a9c(longlong param_1);
int FUN_1c0034c30(longlong param_1,undefined8 *param_2);
int FUN_1c0034fd4(longlong param_1,undefined8 *param_2);
uint FUN_1c00353f8(longlong param_1);
void FUN_1c0035530(longlong param_1,undefined8 param_2);
void FUN_1c0035580(longlong param_1,longlong param_2);
void FUN_1c0035640(longlong param_1);
void FUN_1c0035700(longlong param_1);
undefined4 FUN_1c00357b4(longlong param_1);
int FUN_1c00357d0(longlong param_1);
int FUN_1c00358d0(longlong param_1,undefined8 param_2);
void FUN_1c0035aa0(longlong param_1,undefined *param_2,undefined8 param_3,undefined8 *param_4);
int FUN_1c003718c(longlong param_1,undefined *param_2);
undefined8 FUN_1c00374ac(longlong param_1,undefined *param_2);
int FUN_1c0037be0(longlong param_1);
void FUN_1c0037d38(undefined8 *param_1);
bool FUN_1c0037e40(longlong param_1,ulonglong param_2);
ulonglong FUN_1c0037fc4(longlong param_1);
int FUN_1c0038134(longlong param_1);
void FUN_1c0038230(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 *param_4);
ulonglong FUN_1c003824c(longlong param_1,longlong param_2,longlong param_3);
ulonglong FUN_1c00384c0(longlong param_1);
int FUN_1c00386b0(longlong param_1);
void FUN_1c0038c30(longlong param_1);
void FUN_1c0038c50(longlong param_1);
int FUN_1c0038c70(void);
int FUN_1c0038cd4(longlong param_1);
int FUN_1c003908c(longlong param_1);
undefined4 FUN_1c0039114(longlong param_1);
int FUN_1c00392a8(longlong param_1);
int FUN_1c00393ec(longlong param_1);
void FUN_1c003954c(longlong param_1,longlong param_2,undefined8 param_3);
void FUN_1c00396a8(undefined8 param_1,undefined4 param_2,undefined8 *param_3);
void FUN_1c0039a84(undefined8 param_1,undefined4 param_2,undefined8 *param_3);
int FUN_1c0039fac(undefined8 param_1);
int FUN_1c003a0d4(longlong param_1);
ulonglong FUN_1c003a198(undefined8 *param_1);
int FUN_1c003a2f4(longlong param_1);
int FUN_1c003a3d8(longlong param_1);
int FUN_1c003a454(longlong param_1);
undefined8 FUN_1c003a578(undefined8 param_1);
void FUN_1c003a628(void);
void FUN_1c003a6b0(longlong param_1);
void FUN_1c003a6cc(longlong param_1);
void FUN_1c003a790(longlong param_1);
void FUN_1c003a7f8(longlong param_1);
int FUN_1c003a940(undefined8 *param_1);
int FUN_1c003b140(longlong param_1,uint param_2,undefined8 *param_3);
void FUN_1c003b230(longlong param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4,undefined4 *param_5,undefined4 *param_6,undefined4 *param_7);
void FUN_1c003b32c(longlong param_1,longlong param_2);
void FUN_1c003b450(longlong param_1);
int FUN_1c003b604(undefined8 *param_1);
int FUN_1c003b84c(longlong param_1,undefined8 *param_2);
void FUN_1c003b900(longlong param_1,undefined4 *param_2,undefined1 *param_3,undefined4 *param_4,undefined1 *param_5,undefined1 *param_6);
void FUN_1c003ba48(longlong param_1);
uint FUN_1c003bc1c(longlong param_1);
void FUN_1c003bf00(undefined8 *param_1);
undefined8 FUN_1c003c038(char *param_1,undefined8 *param_2);
undefined4 FUN_1c003c0cc(void);
int FUN_1c003c134(int param_1);
longlong FUN_1c003c174(int param_1);
void FUN_1c003c1f4(byte *param_1,byte *param_2,byte *param_3,byte *param_4);
undefined4 FUN_1c003c2c0(longlong param_1);
int FUN_1c003c490(undefined8 *param_1);
void FUN_1c003c4b8(longlong param_1);
void FUN_1c003c750(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 *param_4);
ulonglong FUN_1c003c770(ulonglong param_1);
int FUN_1c003cb90(undefined8 *param_1);
void FUN_1c003cc90(longlong param_1);
int FUN_1c003ccac(undefined8 *param_1);
void FUN_1c003ceb0(longlong param_1);
void FUN_1c003cf50(longlong param_1);
void FUN_1c003cf70(longlong param_1);
undefined8 FUN_1c003cf90(void);
int FUN_1c003cfa0(undefined8 *param_1);
undefined8 FUN_1c003d06c(uint *param_1,uint param_2,uint param_3,longlong param_4,longlong param_5,int *param_6,int *param_7,uint *param_8,undefined4 *param_9,longlong param_10,ulonglong param_11);
ulonglong FUN_1c003d4a8(longlong param_1,uint *param_2,undefined8 *param_3,longlong *param_4,longlong *param_5);
int FUN_1c003d9f0(undefined8 *param_1);
void FUN_1c003dfa0(longlong param_1);
void FUN_1c003e190(longlong param_1,undefined8 param_2,undefined8 param_3);
void FUN_1c003e33c(longlong param_1,longlong param_2,longlong param_3);
void FUN_1c003e628(longlong param_1,longlong param_2,longlong param_3);
void FUN_1c003e988(longlong param_1,char *param_2,ulonglong *param_3,undefined1 *param_4,longlong param_5);
int FUN_1c003e9e0(longlong param_1,char *param_2,uint param_3,undefined8 param_4,ulonglong *param_5,undefined1 *param_6,undefined1 *param_7,longlong param_8);
void FUN_1c003ed9c(longlong param_1);
void FUN_1c003efe0(longlong param_1,longlong param_2);
ulonglong FUN_1c003f25c(longlong param_1,undefined8 *param_2,longlong param_3);
int FUN_1c003f3bc(longlong param_1,undefined8 *param_2,uint *param_3);
void FUN_1c003f52c(longlong param_1,undefined8 *param_2);
int FUN_1c003f92c(longlong param_1,char param_2);
int FUN_1c003fdf8(longlong param_1);
void FUN_1c003ff78(longlong param_1,undefined8 *param_2);
int FUN_1c004052c(byte *param_1,ulonglong param_2,short *param_3,ulonglong param_4,longlong param_5,int param_6,undefined *param_7,byte param_8);
ulonglong FUN_1c00407fc(uint *param_1,wchar_t *param_2,longlong param_3);
undefined4 FUN_1c00409e0(longlong param_1);
void FUN_1c0040bbc(char *param_1,char *param_2);
void FUN_1c0040c2c(char param_1);
void FUN_1c0040eb0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,uint param_5);
undefined8 FUN_1c0041310(longlong param_1,int param_2,undefined8 *param_3,undefined8 *param_4);
ulonglong FUN_1c0041360(longlong param_1,uint param_2,longlong param_3);
void FUN_1c00413d0(longlong param_1,ulonglong param_2);
int FUN_1c00413e8(longlong param_1,void *param_2,undefined8 param_3,longlong *param_4);
int FUN_1c0041570(longlong param_1,uint *param_2);
void FUN_1c00416d0(longlong param_1,undefined8 param_2);
int FUN_1c0041838(longlong param_1,uint *param_2);
int FUN_1c00419b8(longlong param_1,int param_2,int *param_3,longlong *param_4,undefined4 *param_5);
void FUN_1c0041b94(longlong param_1,int param_2,int param_3,uint param_4);
undefined8 FUN_1c0041cb0(longlong param_1,char *param_2,undefined8 param_3,undefined8 param_4,ulonglong *param_5,undefined1 *param_6,undefined1 *param_7,longlong param_8);
void FUN_1c0041e6c(longlong param_1);
undefined8 FUN_1c00421a0(longlong param_1,undefined1 *param_2,uint param_3);
undefined8 FUN_1c0042250(longlong param_1,undefined4 *param_2,uint param_3);
void FUN_1c004226c(longlong param_1,char param_2);
void FUN_1c00426bc(longlong param_1,char param_2);
void FUN_1c00428c8(longlong param_1);
void FUN_1c0042b30(undefined8 param_1,longlong *param_2);
void FUN_1c0042cd0(longlong param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined8 param_5,undefined8 param_6,undefined8 param_7);
void FUN_1c0042dc0(longlong param_1);
undefined1 FUN_1c0042ebc(longlong param_1,uint param_2,int param_3);
void FUN_1c0042ef8(longlong param_1);
void FUN_1c00431ac(longlong param_1);
void FUN_1c00433f8(longlong param_1);
void FUN_1c004356c(longlong param_1);
void FUN_1c0043804(void);
undefined8 FUN_1c00438f0(int param_1,longlong param_2);
void FUN_1c0043930(longlong param_1,longlong param_2);
void FUN_1c004394c(longlong param_1,longlong param_2,undefined *param_3);
void FUN_1c0043cf8(longlong param_1);
void FUN_1c0043f8c(longlong param_1,char param_2);
void FUN_1c00440f4(longlong param_1,char param_2);
void FUN_1c004440c(longlong param_1);
ulonglong FUN_1c00444c4(longlong param_1,undefined8 *param_2,undefined4 *param_3);
void FUN_1c0044550(undefined8 param_1,int param_2,byte param_3,undefined8 param_4,undefined8 param_5,undefined8 param_6,int *param_7);
void FUN_1c00445cc(char param_1);
void FUN_1c004498c(longlong param_1);
void FUN_1c0044a9c(char param_1);
void FUN_1c0044b3c(void);
void FUN_1c0044be0(uint *param_1);
void FUN_1c0044ea0(longlong param_1,int param_2);
void FUN_1c0044f24(longlong param_1,int param_2,undefined8 param_3,byte *param_4,undefined8 *param_5,int param_6);
void FUN_1c0045328(uint param_1);
int FUN_1c0045590(longlong param_1,char param_2);
undefined4 * FUN_1c00457f8(undefined8 *param_1);
void FUN_1c0045974(longlong param_1,uint *param_2);
ulonglong FUN_1c0045c28(longlong param_1);
undefined8 FUN_1c0045d20(uint param_1,undefined8 *param_2,undefined8 *param_3,undefined4 *param_4);
uint FUN_1c0045d68(longlong param_1,uint param_2,undefined4 param_3,short *param_4);
undefined8 FUN_1c0045ea4(longlong param_1,longlong param_2);
undefined4 FUN_1c0045f20(void);
void FUN_1c0045f30(longlong param_1,longlong *param_2,undefined4 *param_3,undefined4 param_4,undefined4 param_5);
int FUN_1c0046000(longlong param_1);
void FUN_1c00461d4(longlong param_1,longlong param_2,undefined *param_3);
void FUN_1c00464f4(undefined8 param_1,undefined8 param_2,undefined8 param_3);
void FUN_1c0046574(int param_1);
void FUN_1c0046860(undefined8 param_1,int param_2);
void FUN_1c0046b50(undefined8 *param_1);
void FUN_1c0048008(ushort *param_1,byte *param_2);
void FUN_1c0049008(void);
void FUN_1c004903c(longlong param_1,ulonglong *param_2);
void FUN_1c00494d4(undefined1 param_1,uint param_2,undefined8 *param_3,undefined8 param_4);
int FUN_1c00495e4(undefined8 param_1,undefined8 param_2);
int FUN_1c0049798(void);
void FUN_1c0049884(void);
int FUN_1c0049968(undefined8 param_1);
void FUN_1c0049ad0(ulonglong param_1,byte param_2);
void FUN_1c004a8e0(undefined8 param_1);
void FUN_1c004b6ac(byte param_1,longlong *param_2,undefined8 param_3,ulonglong param_4);
void FUN_1c004b80c(byte param_1,longlong param_2);
int FUN_1c004ba18(void);
void FUN_1c004bb54(byte param_1,longlong param_2);

