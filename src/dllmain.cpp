#include <windows.h>
#include <psapi.h>
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cmath>

namespace
{
    FILE* g_log = nullptr;
    HMODULE g_self = nullptr;
    std::uintptr_t g_fcBase = 0;
    std::size_t g_fcSize = 0;

    volatile std::uintptr_t g_cameraPointer = 0;

    std::uintptr_t g_hookSite = 0;
    void* g_hookStub = nullptr;
    std::uint8_t g_original[18]{};
    bool g_hookInstalled = false;
    int g_snapshot = 0;

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

    bool IsReadable(std::uintptr_t p, std::size_t bytes)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!p || !VirtualQuery(reinterpret_cast<void*>(p), &mbi, sizeof(mbi)))
            return false;
        if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
            return false;
        const auto end = p + bytes;
        const auto regionEnd = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        return end <= regionEnd;
    }

    std::vector<std::uintptr_t> Scan(const std::vector<int>& pattern)
    {
        std::vector<std::uintptr_t> hits;
        std::uintptr_t cursor = g_fcBase;
        const std::uintptr_t end = g_fcBase + g_fcSize;

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

                if (size >= pattern.size())
                {
                    for (std::size_t i = 0; i <= size - pattern.size(); ++i)
                    {
                        bool ok = true;
                        for (std::size_t j = 0; j < pattern.size(); ++j)
                        {
                            if (pattern[j] >= 0 &&
                                data[i + j] != static_cast<std::uint8_t>(pattern[j]))
                            {
                                ok = false;
                                break;
                            }
                        }
                        if (ok) hits.push_back(regionBase + i);
                    }
                }
            }

            if (regionEnd <= cursor) break;
            cursor = regionEnd;
        }
        return hits;
    }

    void Emit64(std::uint8_t*& p, std::uintptr_t v)
    {
        std::memcpy(p, &v, sizeof(v));
        p += sizeof(v);
    }

    bool InstallCameraCaptureHook()
    {
        // Unique render camera XYZ block discovered on the user's current FC64.dll.
        const std::vector<int> pattern =
        {
            0xF3,0x41,0x0F,0x11,0x46,0x54,
            0xF3,0x0F,0x10,0x4C,0x24,0x44,
            0xF3,0x41,0x0F,0x11,0x4E,0x58,
            0xF3,0x0F,0x10,0x44,0x24,0x48,
            0xF3,0x41,0x0F,0x11,0x46,0x5C
        };

        const auto hits = Scan(pattern);
        Log("CAMERA_RENDER_XYZ strong signature: %zu match(es)", hits.size());

        if (hits.size() != 1)
        {
            Log("Capture hook not installed: signature is not unique.");
            return false;
        }

        g_hookSite = hits[0];
        Log("Camera render writer = FC64.dll+0x%llX",
            static_cast<unsigned long long>(g_hookSite - g_fcBase));

        constexpr std::size_t stolen = 18;
        std::memcpy(g_original, reinterpret_cast<void*>(g_hookSite), stolen);

        g_hookStub = VirtualAlloc(nullptr, 128, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!g_hookStub)
        {
            Log("VirtualAlloc hook stub failed: %lu", GetLastError());
            return false;
        }

        auto* p = reinterpret_cast<std::uint8_t*>(g_hookStub);

        // push rax
        *p++ = 0x50;

        // mov rax, &g_cameraPointer
        *p++ = 0x48; *p++ = 0xB8;
        Emit64(p, reinterpret_cast<std::uintptr_t>(&g_cameraPointer));

        // mov [rax], r14
        *p++ = 0x4C; *p++ = 0x89; *p++ = 0x30;

        // pop rax
        *p++ = 0x58;

        // Replay the 18 stolen bytes:
        // movss [r14+54],xmm0
        // movss xmm1,[rsp+44]
        // movss [r14+58],xmm1
        std::memcpy(p, g_original, stolen);
        p += stolen;

        // Absolute jump back: FF 25 00000000 [address]
        *p++ = 0xFF; *p++ = 0x25;
        *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
        Emit64(p, g_hookSite + stolen);

        DWORD oldProtect{};
        if (!VirtualProtect(reinterpret_cast<void*>(g_hookSite), stolen,
                            PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            Log("VirtualProtect hook site failed: %lu", GetLastError());
            VirtualFree(g_hookStub, 0, MEM_RELEASE);
            g_hookStub = nullptr;
            return false;
        }

        std::uint8_t patch[stolen]{};
        std::fill(std::begin(patch), std::end(patch), static_cast<std::uint8_t>(0x90));

        patch[0] = 0xFF;
        patch[1] = 0x25;
        patch[2] = patch[3] = patch[4] = patch[5] = 0x00;

        const auto stubAddress = reinterpret_cast<std::uintptr_t>(g_hookStub);
        std::memcpy(patch + 6, &stubAddress, sizeof(stubAddress));

        std::memcpy(reinterpret_cast<void*>(g_hookSite), patch, stolen);
        FlushInstructionCache(GetCurrentProcess(),
                              reinterpret_cast<void*>(g_hookSite), stolen);

        DWORD ignored{};
        VirtualProtect(reinterpret_cast<void*>(g_hookSite), stolen, oldProtect, &ignored);

        g_hookInstalled = true;
        Log("Camera capture hook installed.");
        return true;
    }

    void RemoveCameraCaptureHook()
    {
        if (!g_hookInstalled) return;

        constexpr std::size_t stolen = 18;
        DWORD oldProtect{};
        if (VirtualProtect(reinterpret_cast<void*>(g_hookSite), stolen,
                           PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            std::memcpy(reinterpret_cast<void*>(g_hookSite), g_original, stolen);
            FlushInstructionCache(GetCurrentProcess(),
                                  reinterpret_cast<void*>(g_hookSite), stolen);
            DWORD ignored{};
            VirtualProtect(reinterpret_cast<void*>(g_hookSite), stolen, oldProtect, &ignored);
        }

        g_hookInstalled = false;
        if (g_hookStub)
        {
            VirtualFree(g_hookStub, 0, MEM_RELEASE);
            g_hookStub = nullptr;
        }
        Log("Camera capture hook removed.");
    }

    void DumpCamera(std::uintptr_t cam)
    {
        if (!IsReadable(cam, 0xD0))
        {
            Log("SNAPSHOT %d: camera pointer invalid: 0x%llX",
                g_snapshot, static_cast<unsigned long long>(cam));
            return;
        }

        Log("============================================================");
        Log("SNAPSHOT %d  Camera=0x%llX",
            g_snapshot, static_cast<unsigned long long>(cam));
        Log("============================================================");

        for (std::size_t off = 0; off <= 0xC0; off += 0x10)
        {
            const float* f = reinterpret_cast<const float*>(cam + off);
            const std::uint32_t* u = reinterpret_cast<const std::uint32_t*>(cam + off);

            Log("+%03zX  F: % .7f  % .7f  % .7f  % .7f   U32: %08X %08X %08X %08X",
                off,
                f[0], f[1], f[2], f[3],
                u[0], u[1], u[2], u[3]);
        }

        const float fov = *reinterpret_cast<const float*>(cam + 0x14);
        const float x = *reinterpret_cast<const float*>(cam + 0x54);
        const float y = *reinterpret_cast<const float*>(cam + 0x58);
        const float z = *reinterpret_cast<const float*>(cam + 0x5C);

        Log("Known candidates: FOV(+14)=%.7f  XYZ(+54)=%.7f %.7f %.7f",
            fov, x, y, z);
    }

    bool Pressed(int vk)
    {
        return (GetAsyncKeyState(vk) & 1) != 0;
    }

    DWORD WINAPI MainThread(LPVOID)
    {
        wchar_t logPath[MAX_PATH]{};
        GetModuleFileNameW(nullptr, logPath, MAX_PATH);
        if (auto* slash = wcsrchr(logPath, L'\\'))
            *(slash + 1) = L'\0';
        wcscat_s(logPath, L"FarCry4Camera.log");
        _wfopen_s(&g_log, logPath, L"w");

        Log("FarCry4Camera v0.3");
        Log("Gameplay camera pointer capture + structure probe.");

        HMODULE fc = nullptr;
        while (!(fc = GetModuleHandleW(L"FC64.dll")))
            Sleep(100);

        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), fc, &mi, sizeof(mi)))
        {
            Log("GetModuleInformation failed: %lu", GetLastError());
            return 0;
        }

        g_fcBase = reinterpret_cast<std::uintptr_t>(mi.lpBaseOfDll);
        g_fcSize = static_cast<std::size_t>(mi.SizeOfImage);

        Log("FC64.dll base = 0x%llX", static_cast<unsigned long long>(g_fcBase));
        Log("FC64.dll image size = 0x%zX", g_fcSize);

        if (!InstallCameraCaptureHook())
        {
            Log("No hook. Press END to unload.");
            while (!Pressed(VK_END)) Sleep(20);
            fclose(g_log);
            g_log = nullptr;
            FreeLibraryAndExitThread(g_self, 0);
            return 0;
        }

        Log("Waiting for gameplay camera...");
        Log("When 'Camera captured' appears:");
        Log("  F8 #1 = normal view");
        Log("  turn ~90 degrees right, F8 #2");
        Log("  look clearly up/down, F8 #3");
        Log("  move to another position, F8 #4");
        Log("  END = unload");

        std::uintptr_t last = 0;

        while (true)
        {
            const std::uintptr_t cam = g_cameraPointer;

            if (cam && cam != last)
            {
                last = cam;
                Log("Camera captured: 0x%llX",
                    static_cast<unsigned long long>(cam));
            }

            if (Pressed(VK_F8))
            {
                ++g_snapshot;
                DumpCamera(cam);
            }

            if (Pressed(VK_END))
                break;

            Sleep(10);
        }

        RemoveCameraCaptureHook();
        Log("Unloading.");

        fclose(g_log);
        g_log = nullptr;
        FreeLibraryAndExitThread(g_self, 0);
        return 0;
    }
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        g_self = hinst;
        DisableThreadLibraryCalls(hinst);
        if (HANDLE thread = CreateThread(nullptr, 0, MainThread, nullptr, 0, nullptr))
            CloseHandle(thread);
    }
    return TRUE;
}
