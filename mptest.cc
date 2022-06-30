#include <windows.h>
#include <cstdio>
#include "rsignal.h"

enum class MP_ERROR
{
    InvalidParameter = 0x800C,
};

struct engine_configw_t
{
    char _Blank[0x100];
};

struct UnknownStruct
{
    DWORD data[4];
};

struct engine_boot_t
{
    DWORD ClientMajorVersion;
    DWORD Reserved0;
    const wchar_t* String1;
    size_t Reserved3;
    engine_configw_t* EngineConfig;
    UnknownStruct* UnknownData;
    char Reserved1[0x20];
    char ProductId_0[0x10];
    char Reserved2[0x1C];
    char ProductId_1[0x10];
    char Reserved4[0x2C];
    void* DynamicConfig;
    char _Blank[0x100];
};

struct StreamBufferDescriptor
{
    void* UserData;
    size_t (__fastcall *Read_cb)(StreamBufferDescriptor*, size_t, BYTE*, size_t, size_t *);
    size_t (__fastcall *Write_cb)(StreamBufferDescriptor*, size_t, void*, size_t, size_t *);
    size_t (__fastcall *GetSize_cb)(StreamBufferDescriptor*, size_t*);
    size_t (__fastcall *SetSize_cb)(StreamBufferDescriptor*, size_t);
    const wchar_t* (__fastcall *GetName_cb)(StreamBufferDescriptor*);
    size_t (__fastcall *GetAttribute_cb)(StreamBufferDescriptor*, size_t, size_t, size_t, size_t*);
    size_t (__fastcall *SetAttribute_cb)(StreamBufferDescriptor*);

    const char* filename;
    wchar_t* filename_w;
    FILE* fp;
    size_t file_size;

    StreamBufferDescriptor(const char* filename) :
        UserData(this),
        Read_cb(&StreamBufferDescriptor::Read),
        Write_cb(nullptr),
        GetSize_cb(&StreamBufferDescriptor::GetSize),
        SetSize_cb(nullptr),
        GetName_cb(&StreamBufferDescriptor::GetName),
        GetAttribute_cb(nullptr),
        SetAttribute_cb(nullptr),
        filename(filename),
        filename_w(new wchar_t[strlen(filename) + 1]),
        fp(nullptr),
        file_size(0)
    {
        fp = fopen(filename, "rb");
        if (!fp)
        {
            printf("[-] Could not open the sample file virus.exe!\n");
            return;
        }
        fseek(fp, 0, SEEK_END);
        file_size = ftell(fp);
    }

	~StreamBufferDescriptor()
	{
		if (fp)
			fclose(fp);
		if (filename_w)
			delete[] filename_w;
	}

private:
    static size_t Read(StreamBufferDescriptor* self, size_t offset, BYTE* buffer, size_t size, size_t* nsize)
    {
        fseek(self->fp, offset, SEEK_SET);
        *nsize = fread(buffer, 1, size, self->fp);
        //printf("offset => %llu, %llu bytes has read (%llu bytes wanted).\n", offset, *nsize, size);
        if (*nsize != size)
            return 6;
        return 0;
    }

    static size_t GetSize(StreamBufferDescriptor* self, size_t* size)
    {
        *size = self->file_size;
        return 0;
    }

    static const wchar_t* GetName(StreamBufferDescriptor* self)
    {
        mbstowcs(self->filename_w, self->filename, strlen(self->filename));
        self->filename_w[strlen(self->filename)] = 0;
        return self->filename_w;
    }
};

struct SCANSTRUCT
{
    DWORD Field_0x00;
    DWORD Flags;
    const char* FileName;
    char VirusName[0x20];
    size_t Reversed[0x58];
    const char* FileName2;
    const wchar_t* FileName_WSTR;
    const wchar_t* FileName_WSTR2;
};

enum {
    SCAN_FILENAME        = 1 << 8,
    SCAN_ENCRYPTED       = 1 << 6,
    SCAN_MEMBERNAME      = 1 << 7,
    SCAN_FILETYPE        = 1 << 9,
    SCAN_TOPLEVEL        = 1 << 18,
    SCAN_PACKERSTART     = 1 << 19,
    SCAN_PACKEREND       = 1 << 12,
    SCAN_ISARCHIVE       = 1 << 16,
    SCAN_VIRUSFOUND      = 1 << 27,
    SCAN_CORRUPT         = 1 << 13,
    SCAN_UNKNOWN         = 1 << 15, // I dunno what this means
};

struct ScanReply
{
    DWORD (*ScanCallback_ptr)(SCANSTRUCT*);
    size_t R[2];
    DWORD Flags = 0x7fffffff; // no idea for this.

    ScanReply() : ScanCallback_ptr(&ScanCallback), R{0}
    {}

    static DWORD ScanCallback(SCANSTRUCT* data)
    {
		if ((data->Flags & SCAN_VIRUSFOUND) || data->VirusName[0] != 0)
		{
        	printf("  [!][%s] Flags=%lx, Virus found: %s\n", data->FileName, data->Flags, data->VirusName);
		}
        return 0;
    }
};

/* Placeholder */
struct UfsClientRequest
{
};

/*
struct UfsScanBufferCmd
{
    UfsClientRequest* ufs_client_request;

    virtual void Execute() {}
    virtual void OnComplete(UfsClientRequest&) {}
};
*/

/*
Size of StreamBufferDescriptor must be 32 bytes.
*/
struct StreamBufferScanData
{
    StreamBufferDescriptor* buffer;
    ScanReply* reply;
    size_t Field_0x16;
    UfsClientRequest* ufs_client_request;

    explicit StreamBufferScanData(const char* filename):
        Field_0x16(0),
        ufs_client_request(nullptr)
    {
        buffer = new StreamBufferDescriptor(filename);
        reply = new ScanReply{};
    }

	~StreamBufferScanData()
	{
		delete buffer;
		delete reply;
	}
};

class MpEngine
{
    static constexpr DWORD MAJOR_VERSION = 0x8E00;

    using rsignal_func_t = unsigned int (*)(rsignal_code, void*, DWORD);

public:
    MpEngine()
    {
        engine_handle_ = LoadLibraryA("defender\\MpEngine.dll");
        if (!engine_handle_)
        {
            printf("[-] Failed to load MpEngine.dll: 0x%lx\n", GetLastError());
            return;
        }

        rsignal_ = reinterpret_cast<rsignal_func_t>(GetProcAddress(engine_handle_, "rsignal"));
        if (!rsignal_)
        {
            printf("[-] Failed to get address of function rsignal!\n");
            return;
        }
    }

    bool boot()
    {
        engine_boot_t boot_params{};
        engine_configw_t config{};
        UnknownStruct unk1{};
        boot_params.ClientMajorVersion = MAJOR_VERSION;
        boot_params.String1 = L"defender";
        boot_params.EngineConfig = &config;
        boot_params.UnknownData = &unk1;

        auto result = rsignal_(rsignal_code::RSIG_BOOTENGINE,
            reinterpret_cast<void*>(&boot_params), 0xE8);
        if (result)
        {
            printf("Failed to start mpengine: 0x%lx\n", result);
            return false;
        }
        return true;
    }

    bool scan(const char* filename)
    {
        StreamBufferScanData scan_data(filename);

        auto result = rsignal_(rsignal_code::RSIG_SCAN_STREAMBUFFER, &scan_data, sizeof(scan_data));
        if (result)
        {
            printf("[-] Failed to perform scanning: 0x%lx\n", result);
            return false;
        }
        return true;
    }

    bool is_ready() const noexcept { return rsignal_ != nullptr; }

private:
    HMODULE engine_handle_;
    rsignal_func_t rsignal_;
};

int main(int argc, char** argv)
{
    MpEngine engine;

    if (argc < 2)
    {
        printf("Usage: %s <file to scan> [file 2] [file 3] [...]\n", argv[0]);
        return 1;
    }

    __try
    {
        printf("Preparing defender engine...\n");
        if (engine.is_ready() && engine.boot())
        {
	        for (int i = 1; i < argc; ++i)
            {
                printf("Scanning %s...\n", argv[i]);
                engine.scan(argv[i]);
            }
            printf("Completed.\n");
            return 0;
        }
    }
    __except(1)
    {
        printf("Exception: %lx\n", GetExceptionCode());
        return 5;
    }

    return 5;
}
