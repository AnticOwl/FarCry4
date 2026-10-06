#include <windows.h>
#include <psapi.h>
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <vector>
#include <string>
#include <algorithm>

namespace
{
    FILE* g_log = nullptr;

    void Log(const char* fmt, ...)
    {
        if (!g_log) return;
        va_list args;
        va_start(args, fmt);
        vfprintf(g_log, fmt, args);
        va_end(args);
        fputc('\n', g_log);
        fflush(g_log);
    }

    bool IsExecutableProtect(DWORD p)
    {
        p &= 0xFF;
        return p == PAGE_EXECUTE ||
               p == PAGE_EXECUTE_READ ||
               p == PAGE_EXECUTE_READWRITE ||
               p == PAGE_EXECUTE_WRITECOPY;
    }

    struct Pattern
    {
        const char* name;
        std::vector<int> bytes; // -1 = wildcard
    };

    Pattern MakePattern(const char* name, std::initializer_list<int> b)
    {
        return Pattern{name, std::vector<int>(b)};
    }

    std::vector<std::uintptr_t> ScanPattern(
        std::uintptr_t moduleBase,
        std::size_t moduleSize,
        const Pattern& pat)
    {
        std::vector<std::uintptr_t> result;
        std::uintptr_t cursor = moduleBase;
        const std::uintptr_t end = moduleBase + moduleSize;

        while (cursor < end)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<void*>(cursor), &mbi, sizeof(mbi)))
                break;

            const auto regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            auto regionEnd = regionBase + mbi.RegionSize;
            if (regionEnd > end) regionEnd = end;

            if (mbi.State == MEM_COMMIT &&
                !(mbi.Protect & PAGE_GUARD) &&
                !(mbi.Protect & PAGE_NOACCESS) &&
                IsExecutableProtect(mbi.Protect))
            {
                const auto* data = reinterpret_cast<const std::uint8_t*>(regionBase);
                const std::size_t size = regionEnd - regionBase;

                if (size >= pat.bytes.size())
                {
                    for (std::size_t i = 0; i <= size - pat.bytes.size(); ++i)
                    {
                        bool ok = true;
                        for (std::size_t j = 0; j < pat.bytes.size(); ++j)
                        {
                            const int wanted = pat.bytes[j];
                            if (wanted >= 0 && data[i + j] != static_cast<std::uint8_t>(wanted))
                            {
                                ok = false;
                                break;
                            }
                        }
                        if (ok)
                            result.push_back(regionBase + i);
                    }
                }
            }

            if (regionEnd <= cursor) break;
            cursor = regionEnd;
        }

        return result;
    }

    void DumpBytes(std::uintptr_t address, int before = 16, int after = 32)
    {
        const auto start = address - before;
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<void*>(start), &mbi, sizeof(mbi)))
            return;

        const auto regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        const auto regionEnd = regionBase + mbi.RegionSize;
        if (start < regionBase || address + after > regionEnd)
            return;

        const auto* p = reinterpret_cast<const std::uint8_t*>(start);
        char line[1024]{};
        int n = std::snprintf(line, sizeof(line), "    bytes:");
        for (int i = 0; i < before + after && n > 0 && n < int(sizeof(line) - 4); ++i)
        {
            if (i == before)
                n += std::snprintf(line + n, sizeof(line) - n, " [");
            n += std::snprintf(line + n, sizeof(line) - n, "%02X", p[i]);
            if (i == before)
                n += std::snprintf(line + n, sizeof(line) - n, "]");
            n += std::snprintf(line + n, sizeof(line) - n, " ");
        }
        Log("%s", line);
    }

    void ReportPattern(
        std::uintptr_t base,
        std::size_t imageSize,
        const Pattern& pat,
        std::size_t maxDump = 24)
    {
        const auto hits = ScanPattern(base, imageSize, pat);
        Log("%s: %zu match(es)", pat.name, hits.size());

        const std::size_t show = std::min(maxDump, hits.size());
        for (std::size_t i = 0; i < show; ++i)
        {
            Log("  [%zu] FC64.dll+0x%llX  VA=0x%llX",
                i,
                static_cast<unsigned long long>(hits[i] - base),
                static_cast<unsigned long long>(hits[i]));
            DumpBytes(hits[i]);
        }

        if (hits.size() > show)
            Log("  ... %zu additional match(es) omitted", hits.size() - show);
    }

    DWORD WINAPI MainThread(LPVOID self)
    {
        wchar_t logPath[MAX_PATH]{};
        GetModuleFileNameW(nullptr, logPath, MAX_PATH);
        if (auto* slash = wcsrchr(logPath, L'\\'))
            *(slash + 1) = L'\0';
        wcscat_s(logPath, L"FarCry4Camera.log");
        _wfopen_s(&g_log, logPath, L"w");

        Log("FarCry4Camera v0.2");
        Log("Runtime camera signature discovery build.");

        HMODULE fc = nullptr;
        while (!(fc = GetModuleHandleW(L"FC64.dll")))
            Sleep(100);

        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), fc, &mi, sizeof(mi)))
        {
            Log("GetModuleInformation failed: %lu", GetLastError());
            fclose(g_log);
            FreeLibraryAndExitThread(static_cast<HMODULE>(self), 1);
            return 0;
        }

        const auto base = reinterpret_cast<std::uintptr_t>(mi.lpBaseOfDll);
        const auto size = static_cast<std::size_t>(mi.SizeOfImage);

        Log("FC64.dll base = 0x%llX", static_cast<unsigned long long>(base));
        Log("FC64.dll image size = 0x%zX", size);

        // Old FC4 camera read. This short signature is expected to have several
        // matches; the surrounding bytes let us derive a stable AOB for this build.
        ReportPattern(base, size,
            MakePattern("READ_FOV_RCXP14",
                {0xF3,0x0F,0x10,0x41,0x14}));

        // Old camera structure copy: X/Y/Z are copied from RDX to RCX.
        // Strong signature spanning all three fields.
        ReportPattern(base, size,
            MakePattern("CAMERA_COPY_XYZ",
                {0x89,0x41,0x4C,0x8B,0x42,0x50,
                 0x89,0x41,0x50,0x8B,0x42,0x54,
                 0x89,0x41,0x54,0x8B,0x42,0x58}));

        // Old render camera XYZ writers. The six bytes between each movss are
        // wildcarded because those instructions may differ between patches.
        ReportPattern(base, size,
            MakePattern("CAMERA_RENDER_XYZ",
                {0xF3,0x41,0x0F,0x11,0x46,0x54,
                 -1,-1,-1,-1,-1,-1,
                 0xF3,0x41,0x0F,0x11,0x4E,0x58,
                 -1,-1,-1,-1,-1,-1,
                 0xF3,0x41,0x0F,0x11,0x46,0x5C}));

        ReportPattern(base, size,
            MakePattern("COPY_FOV_DWORD",
                {0x89,0x41,0x0C,0x8B,0x42,0x10}));

        // Generic movss [reg+14],xmm? candidates used to recover the FOV writer.
        ReportPattern(base, size,
            MakePattern("WRITE_FLOAT_P14",
                {0xF3,0x0F,0x11,-1,0x14}));

        // Generic scalar reads around the old rotation block.
        ReportPattern(base, size,
            MakePattern("READ_FLOAT_P6C",
                {0xF3,0x0F,0x10,-1,0x6C}));

        ReportPattern(base, size,
            MakePattern("READ_FLOAT_P70",
                {0xF3,0x0F,0x10,-1,0x70}));

        ReportPattern(base, size,
            MakePattern("READ_FLOAT_P74",
                {0xF3,0x0F,0x10,-1,0x74}));

        Log("Discovery complete.");
        Log("Move the gameplay camera for a few seconds, then press END.");

        while (!(GetAsyncKeyState(VK_END) & 1))
            Sleep(20);

        Log("Unloading.");
        fclose(g_log);
        g_log = nullptr;
        FreeLibraryAndExitThread(static_cast<HMODULE>(self), 0);
        return 0;
    }
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinst);
        if (HANDLE thread = CreateThread(nullptr, 0, MainThread, hinst, 0, nullptr))
            CloseHandle(thread);
    }
    return TRUE;
}
