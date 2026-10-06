#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <cmath>
#include <atomic>
#include <array>
#include <algorithm>
#include <iterator>

namespace
{
    constexpr wchar_t kTargetModule[] = L"FC64.dll";
    constexpr std::uintptr_t kCameraReadRva = 0x29B0C6;

    struct PatchSite
    {
        std::uintptr_t rva;
        const std::uint8_t* expected;
        std::size_t size;
        std::array<std::uint8_t, 8> original{};
        bool valid = false;
    };

    constexpr std::uint8_t kPosWriter0[] = { 0x89, 0x41, 0x4C };
    constexpr std::uint8_t kPosWriter1[] = { 0x89, 0x41, 0x50 };
    constexpr std::uint8_t kPosWriter2[] = { 0x89, 0x41, 0x54 };
    constexpr std::uint8_t kPosWriter3[] = { 0xF3, 0x41, 0x0F, 0x11, 0x46, 0x54 };
    constexpr std::uint8_t kPosWriter4[] = { 0xF3, 0x41, 0x0F, 0x11, 0x4E, 0x58 };
    constexpr std::uint8_t kPosWriter5[] = { 0xF3, 0x41, 0x0F, 0x11, 0x46, 0x5C };

    PatchSite g_positionWriters[] =
    {
        { 0x1EBA1C, kPosWriter0, sizeof(kPosWriter0) },
        { 0x1EBA22, kPosWriter1, sizeof(kPosWriter1) },
        { 0x1EBA28, kPosWriter2, sizeof(kPosWriter2) },
        { 0x890CDB, kPosWriter3, sizeof(kPosWriter3) },
        { 0x890CE7, kPosWriter4, sizeof(kPosWriter4) },
        { 0x890CF3, kPosWriter5, sizeof(kPosWriter5) },
    };

    struct Vec3 { float x, y, z; };

    struct CameraState
    {
        float fov = 0.0f;
        Vec3 pos{};
        Vec3 rot{};
    };

    std::uintptr_t g_fcBase = 0;
    std::atomic<std::uintptr_t> g_cameraPrimary{ 0 };
    std::atomic<std::uintptr_t> g_cameraSecondary{ 0 };
    std::atomic<bool> g_running{ true };

    FILE* g_log = nullptr;
    bool g_freecam = false;
    CameraState g_saved{};
    CameraState g_cam{};

    bool KeyDown(int vk) { return (GetAsyncKeyState(vk) & 0x8000) != 0; }

    bool KeyPressed(int vk)
    {
        static bool previous[256]{};
        const bool now = KeyDown(vk);
        const bool pressed = now && !previous[vk];
        previous[vk] = now;
        return pressed;
    }

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

    bool IsReadable(std::uintptr_t p, std::size_t bytes)
    {
        if (p < 0x10000) return false;
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<void*>(p), &mbi, sizeof(mbi))) return false;
        if (mbi.State != MEM_COMMIT) return false;
        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return false;
        const auto end = p + bytes;
        const auto regionEnd = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        return end <= regionEnd;
    }

    bool ReadCamera(std::uintptr_t p, CameraState& out)
    {
        if (!IsReadable(p, 0x78)) return false;
        out.fov = *reinterpret_cast<float*>(p + 0x14);
        out.pos = *reinterpret_cast<Vec3*>(p + 0x54);
        out.rot = *reinterpret_cast<Vec3*>(p + 0x6C);

        return std::isfinite(out.fov) &&
               std::isfinite(out.pos.x) &&
               std::isfinite(out.pos.y) &&
               std::isfinite(out.pos.z) &&
               std::isfinite(out.rot.x) &&
               std::isfinite(out.rot.y) &&
               std::isfinite(out.rot.z);
    }

    void WriteCamera(std::uintptr_t p, const CameraState& s)
    {
        if (!IsReadable(p, 0x78)) return;
        *reinterpret_cast<float*>(p + 0x14) = s.fov;
        *reinterpret_cast<Vec3*>(p + 0x54) = s.pos;
        *reinterpret_cast<Vec3*>(p + 0x6C) = s.rot;
    }

    bool ValidatePatch(PatchSite& s)
    {
        const auto p = g_fcBase + s.rva;
        if (!IsReadable(p, s.size)) return false;

        auto* bytes = reinterpret_cast<const std::uint8_t*>(p);
        for (std::size_t i = 0; i < s.size; ++i)
            if (bytes[i] != s.expected[i])
                return false;

        for (std::size_t i = 0; i < s.size; ++i)
            s.original[i] = bytes[i];

        s.valid = true;
        return true;
    }

    bool Patch(PatchSite& s, bool nop)
    {
        if (!s.valid) return false;

        auto* p = reinterpret_cast<std::uint8_t*>(g_fcBase + s.rva);
        DWORD oldProt{};
        if (!VirtualProtect(p, s.size, PAGE_EXECUTE_READWRITE, &oldProt))
            return false;

        if (nop)
            std::fill_n(p, s.size, static_cast<std::uint8_t>(0x90));
        else
            for (std::size_t i = 0; i < s.size; ++i)
                p[i] = s.original[i];

        FlushInstructionCache(GetCurrentProcess(), p, s.size);
        DWORD dummy{};
        VirtualProtect(p, s.size, oldProt, &dummy);
        return true;
    }

    void PatchPositionWriters(bool nop)
    {
        for (auto& s : g_positionWriters)
            if (s.valid)
                Patch(s, nop);
    }

    struct XINPUT_GAMEPAD_LOCAL
    {
        WORD wButtons;
        BYTE bLeftTrigger;
        BYTE bRightTrigger;
        SHORT sThumbLX;
        SHORT sThumbLY;
        SHORT sThumbRX;
        SHORT sThumbRY;
    };

    struct XINPUT_STATE_LOCAL
    {
        DWORD dwPacketNumber;
        XINPUT_GAMEPAD_LOCAL Gamepad;
    };

    using XInputGetState_t = DWORD (WINAPI*)(DWORD, XINPUT_STATE_LOCAL*);
    XInputGetState_t g_xinputGetState = nullptr;

    constexpr WORD XBTN_LEFT_SHOULDER  = 0x0100;
    constexpr WORD XBTN_RIGHT_SHOULDER = 0x0200;
    constexpr WORD XBTN_B = 0x2000;
    constexpr WORD XBTN_X = 0x4000;
    constexpr WORD XBTN_Y = 0x8000;

    void InitXInput()
    {
        const wchar_t* dlls[] = { L"xinput1_4.dll", L"xinput1_3.dll", L"xinput9_1_0.dll" };
        for (auto* dll : dlls)
        {
            if (auto mod = LoadLibraryW(dll))
            {
                g_xinputGetState = reinterpret_cast<XInputGetState_t>(
                    GetProcAddress(mod, "XInputGetState"));
                if (g_xinputGetState)
                {
                    Log("XInput: %ls", dll);
                    return;
                }
            }
        }
        Log("XInput unavailable.");
    }

    float Stick(SHORT v, SHORT deadzone = 7000)
    {
        const float f = static_cast<float>(v);
        const float a = std::fabs(f);
        if (a <= deadzone) return 0.0f;
        const float sign = f < 0 ? -1.0f : 1.0f;
        return sign * std::clamp((a - deadzone) / (32767.0f - deadzone), 0.0f, 1.0f);
    }

    float Trigger(BYTE v, BYTE deadzone = 25)
    {
        if (v <= deadzone) return 0.0f;
        return std::clamp((float(v) - deadzone) / (255.0f - deadzone), 0.0f, 1.0f);
    }

    void Basis(const Vec3& rot, Vec3& forward, Vec3& right, Vec3& up)
    {
        const float pitch = rot.x;
        const float roll  = rot.y;
        const float yaw   = rot.z;

        const float cp = std::cos(pitch);
        const float sp = std::sin(pitch);
        const float cy = std::cos(yaw);
        const float sy = std::sin(yaw);

        forward = { cp * cy, cp * sy, sp };
        right = { -sy, cy, 0.0f };
        up =
        {
            right.y * forward.z - right.z * forward.y,
            right.z * forward.x - right.x * forward.z,
            right.x * forward.y - right.y * forward.x
        };

        if (roll != 0.0f)
        {
            const float cr = std::cos(roll);
            const float sr = std::sin(roll);
            Vec3 r2
            {
                right.x * cr + up.x * sr,
                right.y * cr + up.y * sr,
                right.z * cr + up.z * sr
            };
            Vec3 u2
            {
                up.x * cr - right.x * sr,
                up.y * cr - right.y * sr,
                up.z * cr - right.z * sr
            };
            right = r2;
            up = u2;
        }
    }

    void Add(Vec3& dst, const Vec3& dir, float amount)
    {
        dst.x += dir.x * amount;
        dst.y += dir.y * amount;
        dst.z += dir.z * amount;
    }

    void Update(float dt)
    {
        float moveF = 0.0f;
        float moveR = 0.0f;
        float moveU = 0.0f;
        float yaw = 0.0f;
        float pitch = 0.0f;
        float roll = 0.0f;

        if (KeyDown(VK_NUMPAD8)) moveF += 1.0f;
        if (KeyDown(VK_NUMPAD5)) moveF -= 1.0f;
        if (KeyDown(VK_NUMPAD6)) moveR += 1.0f;
        if (KeyDown(VK_NUMPAD4)) moveR -= 1.0f;
        if (KeyDown(VK_NUMPAD9)) moveU += 1.0f;
        if (KeyDown(VK_NUMPAD7)) moveU -= 1.0f;

        if (KeyDown(VK_RIGHT)) yaw += 1.0f;
        if (KeyDown(VK_LEFT)) yaw -= 1.0f;
        if (KeyDown(VK_UP)) pitch += 1.0f;
        if (KeyDown(VK_DOWN)) pitch -= 1.0f;
        if (KeyDown(VK_NUMPAD3)) roll += 1.0f;
        if (KeyDown(VK_NUMPAD1)) roll -= 1.0f;

        bool padSlow = false;
        bool padFast = false;
        static WORD oldButtons = 0;

        if (g_xinputGetState)
        {
            XINPUT_STATE_LOCAL st{};
            if (g_xinputGetState(0, &st) == ERROR_SUCCESS)
            {
                const auto& gp = st.Gamepad;
                moveR += Stick(gp.sThumbLX);
                moveF += Stick(gp.sThumbLY);
                yaw += Stick(gp.sThumbRX);
                pitch += Stick(gp.sThumbRY);
                moveU += Trigger(gp.bRightTrigger);
                moveU -= Trigger(gp.bLeftTrigger);

                if (gp.wButtons & XBTN_RIGHT_SHOULDER) roll += 1.0f;
                if (gp.wButtons & XBTN_LEFT_SHOULDER)  roll -= 1.0f;

                padSlow = (gp.wButtons & XBTN_X) != 0;
                padFast = (gp.wButtons & XBTN_Y) != 0;

                if ((gp.wButtons & XBTN_B) && !(oldButtons & XBTN_B))
                    g_cam.rot.y = 0.0f;

                oldButtons = gp.wButtons;
            }
        }

        float speed = 4.0f;
        if (KeyDown(VK_SHIFT) || padFast) speed *= 4.0f;
        if (KeyDown(VK_CONTROL) || padSlow) speed *= 0.25f;
        if (KeyDown(VK_MENU)) speed *= 0.05f;

        const float rotSpeed = 1.25f;
        g_cam.rot.z += yaw   * rotSpeed * dt;
        g_cam.rot.x += pitch * rotSpeed * dt;
        g_cam.rot.y += roll  * rotSpeed * dt;

        if (KeyPressed(VK_NUMPAD2))
            g_cam.rot.y = 0.0f;

        if (KeyDown(VK_ADD))      g_cam.fov += 0.5f * dt;
        if (KeyDown(VK_SUBTRACT)) g_cam.fov -= 0.5f * dt;

        Vec3 f{}, r{}, u{};
        Basis(g_cam.rot, f, r, u);
        Add(g_cam.pos, f, moveF * speed * dt);
        Add(g_cam.pos, r, moveR * speed * dt);
        Add(g_cam.pos, u, moveU * speed * dt);

        const auto p1 = g_cameraPrimary.load();
        const auto p2 = g_cameraSecondary.load();
        WriteCamera(p1, g_cam);
        if (p2 && p2 != p1)
            WriteCamera(p2, g_cam);
    }

    bool EnableFreecam()
    {
        const auto p = g_cameraPrimary.load();
        if (!p)
        {
            Log("FREECAM ON failed: no camera pointer captured.");
            return false;
        }

        if (!ReadCamera(p, g_saved))
        {
            Log("FREECAM ON failed: camera state invalid.");
            return false;
        }

        g_cam = g_saved;
        PatchPositionWriters(true);
        g_freecam = true;
        Log("FREECAM ON");
        return true;
    }

    void DisableFreecam()
    {
        if (!g_freecam) return;

        const auto p1 = g_cameraPrimary.load();
        const auto p2 = g_cameraSecondary.load();
        WriteCamera(p1, g_saved);
        if (p2 && p2 != p1)
            WriteCamera(p2, g_saved);

        PatchPositionWriters(false);
        g_freecam = false;
        Log("FREECAM OFF");
    }

    void ProbeCameraSite()
    {
        const auto site = g_fcBase + kCameraReadRva;
        constexpr std::uint8_t expected[] = { 0xF3, 0x0F, 0x10, 0x41, 0x14 };

        if (!IsReadable(site, sizeof(expected)))
        {
            Log("Camera read site unreadable.");
            return;
        }

        auto* b = reinterpret_cast<const std::uint8_t*>(site);
        const bool match = std::equal(std::begin(expected), std::end(expected), b);

        Log("Camera read site %s at FC64.dll+0x%llX",
            match ? "MATCH" : "MISMATCH",
            static_cast<unsigned long long>(kCameraReadRva));

        Log("Bytes: %02X %02X %02X %02X %02X",
            b[0], b[1], b[2], b[3], b[4]);
    }

    DWORD WINAPI MainThread(LPVOID self)
    {
        wchar_t logPath[MAX_PATH]{};
        GetModuleFileNameW(nullptr, logPath, MAX_PATH);
        if (auto* slash = wcsrchr(logPath, L'\\'))
            *(slash + 1) = L'\0';

        wcscat_s(logPath, L"FarCry4Camera.log");
        _wfopen_s(&g_log, logPath, L"w");

        Log("FarCry4Camera v0.1");
        Log("Camera-only validation build.");

        HMODULE fc = nullptr;
        while (g_running && !(fc = GetModuleHandleW(kTargetModule)))
            Sleep(100);

        if (!fc)
            return 0;

        g_fcBase = reinterpret_cast<std::uintptr_t>(fc);
        Log("FC64.dll base = 0x%llX", static_cast<unsigned long long>(g_fcBase));

        int valid = 0;
        for (auto& s : g_positionWriters)
        {
            if (ValidatePatch(s))
            {
                ++valid;
                Log("Writer MATCH: FC64.dll+0x%llX",
                    static_cast<unsigned long long>(s.rva));
            }
            else
            {
                const auto p = g_fcBase + s.rva;
                if (IsReadable(p, s.size))
                {
                    auto* b = reinterpret_cast<const std::uint8_t*>(p);
                    char line[128]{};
                    int n = std::snprintf(line, sizeof(line),
                        "Writer MISMATCH: FC64.dll+0x%llX bytes:",
                        static_cast<unsigned long long>(s.rva));

                    for (std::size_t i = 0; i < s.size && n > 0 && n < int(sizeof(line) - 4); ++i)
                        n += std::snprintf(line + n, sizeof(line) - n, " %02X", b[i]);

                    Log("%s", line);
                }
                else
                {
                    Log("Writer unreadable: FC64.dll+0x%llX",
                        static_cast<unsigned long long>(s.rva));
                }
            }
        }

        Log("Writers validated = %d/%zu", valid, std::size(g_positionWriters));
        ProbeCameraSite();
        InitXInput();

        Log("Validation complete.");
        Log("Press END to unload.");

        while (g_running)
        {
            if (KeyPressed(VK_END))
                g_running = false;

            if (KeyPressed(VK_INSERT))
                Log("INSERT pressed - freecam not armed in validation build.");

            Sleep(10);
        }

        DisableFreecam();
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
