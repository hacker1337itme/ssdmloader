// ======================================================================
// SSDM (System Service Dispatch Monitor) Loader Hook Implementation
// Complete Single-File Implementation
// Educational Purpose - Kernel/Driver Research
// ======================================================================

#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include <string>
#include <psapi.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <fstream>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

// ======================================================================
// 1. CONSTANTS AND DEFINITIONS
// ======================================================================

#define SSDM_HOOK_VERSION 0x1337
#define HOOK_FLAG_ACTIVE 0x1
#define HOOK_FLAG_STEALTH 0x2

// NTSTATUS codes
#define STATUS_SUCCESS 0x00000000
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

// System call numbers (may vary by Windows version)
#define SYS_NT_CREATE_SECTION 0x37
#define SYS_NT_MAP_VIEW_OF_SECTION 0x3A
#define SYS_LDR_LOAD_DLL 0xFFFF // Not a real syscall, for illustration

// ======================================================================
// 2. STRUCTURES AND TYPES
// ======================================================================

typedef struct _SSDM_HOOK_CONTEXT {
    ULONG_PTR OriginalFunction;      // Original function address
    ULONG_PTR HookFunction;          // Hook function address
    ULONG_PTR Trampoline;            // Trampoline address
    SIZE_T HookSize;                 // Size of hook
    DWORD Protection;                // Original memory protection
    BOOL IsActive;                   // Hook status
    CHAR FunctionName[64];           // Function name
} SSDM_HOOK_CONTEXT, *PSSDM_HOOK_CONTEXT;

typedef struct _SSDM_SHELLCODE_INFO {
    PVOID Buffer;                    // Shellcode buffer
    SIZE_T Size;                     // Shellcode size
    DWORD Protection;                // Memory protection
    BOOL IsExecutable;               // Is buffer executable
    ULONG_PTR EntryPoint;            // Shellcode entry point
} SSDM_SHELLCODE_INFO, *PSSDM_SHELLCODE_INFO;

// NT function prototypes
typedef NTSTATUS(NTAPI* _NtCreateSection)(
    PHANDLE SectionHandle,
    ULONG DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG PageAttributess,
    ULONG SectionAttributes,
    HANDLE FileHandle
);

typedef NTSTATUS(NTAPI* _NtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

typedef NTSTATUS(NTAPI* _LdrLoadDll)(
    PWSTR SearchPath,
    PULONG LoadFlags,
    PUNICODE_STRING Name,
    PVOID* BaseAddress
);

// ======================================================================
// 3. GLOBAL VARIABLES
// ======================================================================

static SSDM_HOOK_CONTEXT g_LdrLoadDllHook = { 0 };
static SSDM_HOOK_CONTEXT g_NtCreateSectionHook = { 0 };
static SSDM_SHELLCODE_INFO g_ShellcodeInfo = { 0 };
static CRITICAL_SECTION g_CriticalSection;

// Original function pointers
static _LdrLoadDll OriginalLdrLoadDll = nullptr;
static _NtCreateSection OriginalNtCreateSection = nullptr;
static _NtMapViewOfSection OriginalNtMapViewOfSection = nullptr;

// ======================================================================
// 4. UTILITY FUNCTIONS
// ======================================================================

// Print with SSDM prefix
void SSDM_LOG(const char* format, ...) {
    char buffer[512];
    va_list args;
    va_start(args, format);
    vsprintf_s(buffer, format, args);
    va_end(args);
    
    printf("[SSDM] %s\n", buffer);
}

// Get process ID by name
DWORD GetProcessIdByName(const wchar_t* processName) {
    DWORD processId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W processEntry = { 0 };
        processEntry.dwSize = sizeof(PROCESSENTRY32W);
        
        if (Process32FirstW(snapshot, &processEntry)) {
            do {
                if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
                    processId = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }
    
    return processId;
}

// Get module base address
ULONG_PTR GetModuleBase(const wchar_t* moduleName) {
    HMODULE hModule = GetModuleHandleW(moduleName);
    return reinterpret_cast<ULONG_PTR>(hModule);
}

// Disable memory protection
BOOL DisableMemoryProtection(PVOID address, SIZE_T size, PDWORD oldProtect) {
    return VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, oldProtect);
}

// Restore memory protection
BOOL RestoreMemoryProtection(PVOID address, SIZE_T size, DWORD oldProtect) {
    DWORD dummy;
    return VirtualProtect(address, size, oldProtect, &dummy);
}

// ======================================================================
// 5. SHELLCODE MANAGEMENT
// ======================================================================

// Example shellcode: MessageBox "SSDM Active"
#ifdef _WIN64
// x64 MessageBox shellcode
std::vector<BYTE> GenerateMessageBoxShellcode() {
    // This is a position-independent MessageBox shellcode
    std::vector<BYTE> shellcode = {
        // Save non-volatile registers
        0x48, 0x83, 0xEC, 0x28,                     // sub rsp, 0x28
        
        // Load user32.dll
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // rcx = "user32.dll"
        0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // rdx = LoadLibraryA
        0xFF, 0xD2,                                 // call rdx
        
        // Get MessageBoxA address
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // rcx = "MessageBoxA"
        0x48, 0x89, 0xC2,                             // mov rdx, rax
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // rax = GetProcAddress
        0xFF, 0xD0,                                 // call rax
        
        // Call MessageBoxA
        0x48, 0x31, 0xC9,                             // xor rcx, rcx
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // rcx = "SSDM Active"
        0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // rdx = "Loader Hook"
        0x49, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,     // mov r8, 0
        0xFF, 0xD0,                                 // call rax
        
        // Restore stack and return
        0x48, 0x83, 0xC4, 0x28,                     // add rsp, 0x28
        0xC3                                        // ret
    };
    
    // In a real implementation, you would resolve addresses here
    return shellcode;
}
#else
// x86 MessageBox shellcode
std::vector<BYTE> GenerateMessageBoxShellcode() {
    std::vector<BYTE> shellcode = {
        // pushad
        0x60,
        
        // Load user32.dll
        0x68, 0x00, 0x00, 0x00, 0x00,                 // push "user32.dll"
        0xB8, 0x00, 0x00, 0x00, 0x00,                 // mov eax, LoadLibraryA
        0xFF, 0xD0,                                 // call eax
        
        // Get MessageBoxA
        0x68, 0x00, 0x00, 0x00, 0x00,                 // push "MessageBoxA"
        0x50,                                       // push eax
        0xB8, 0x00, 0x00, 0x00, 0x00,                 // mov eax, GetProcAddress
        0xFF, 0xD0,                                 // call eax
        
        // Call MessageBoxA
        0x6A, 0x00,                                 // push 0
        0x68, 0x00, 0x00, 0x00, 0x00,                 // push "Loader Hook"
        0x68, 0x00, 0x00, 0x00, 0x00,                 // push "SSDM Active"
        0x6A, 0x00,                                 // push 0
        0xFF, 0xD0,                                 // call eax
        
        // popad and return
        0x61,                                       // popad
        0xC3                                        // ret
    };
    return shellcode;
}
#endif

// Allocate executable memory for shellcode
BOOL AllocateExecutableMemory(PVOID* buffer, SIZE_T size) {
    // Method 1: Normal VirtualAlloc
    *buffer = VirtualAlloc(nullptr, size, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE);
    
    if (*buffer) {
        return TRUE;
    }
    
    // Method 2: Use NtCreateSection for more stealth
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    _NtCreateSection NtCreateSection = (_NtCreateSection)
        GetProcAddress(ntdll, "NtCreateSection");
    
    if (!NtCreateSection) {
        return FALSE;
    }
    
    HANDLE sectionHandle = nullptr;
    LARGE_INTEGER sectionSize = { .QuadPart = static_cast<LONGLONG>(size) };
    
    NTSTATUS status = NtCreateSection(
        &sectionHandle,
        SECTION_ALL_ACCESS,
        nullptr,
        &sectionSize,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        nullptr
    );
    
    if (NT_SUCCESS(status)) {
        _NtMapViewOfSection NtMapViewOfSection = (_NtMapViewOfSection)
            GetProcAddress(ntdll, "NtMapViewOfSection");
        
        if (NtMapViewOfSection) {
            SIZE_T viewSize = 0;
            status = NtMapViewOfSection(
                sectionHandle,
                GetCurrentProcess(),
                buffer,
                0, size,
                nullptr,
                &viewSize,
                ViewShare,
                0,
                PAGE_EXECUTE_READWRITE
            );
            
            if (NT_SUCCESS(status)) {
                CloseHandle(sectionHandle);
                return TRUE;
            }
        }
        CloseHandle(sectionHandle);
    }
    
    return FALSE;
}

// Prepare shellcode for execution
BOOL PrepareShellcode() {
    EnterCriticalSection(&g_CriticalSection);
    
    // Generate shellcode
    std::vector<BYTE> shellcode = GenerateMessageBoxShellcode();
    
    // Allocate executable memory
    PVOID buffer = nullptr;
    if (!AllocateExecutableMemory(&buffer, shellcode.size())) {
        SSDM_LOG("Failed to allocate executable memory");
        LeaveCriticalSection(&g_CriticalSection);
        return FALSE;
    }
    
    // Copy shellcode
    memcpy(buffer, shellcode.data(), shellcode.size());
    
    // Update shellcode info
    g_ShellcodeInfo.Buffer = buffer;
    g_ShellcodeInfo.Size = shellcode.size();
    g_ShellcodeInfo.Protection = PAGE_EXECUTE_READWRITE;
    g_ShellcodeInfo.IsExecutable = TRUE;
    g_ShellcodeInfo.EntryPoint = reinterpret_cast<ULONG_PTR>(buffer);
    
    // Flush instruction cache
    FlushInstructionCache(GetCurrentProcess(), buffer, shellcode.size());
    
    SSDM_LOG("Shellcode prepared at 0x%p", buffer);
    LeaveCriticalSection(&g_CriticalSection);
    return TRUE;
}

// ======================================================================
// 6. HOOKING ENGINE
// ======================================================================

// Create trampoline function
PVOID CreateTrampoline(PVOID originalFunction, PVOID hookFunction, SIZE_T* hookSize) {
#ifdef _WIN64
    // x64 requires 12-14 bytes for a detour
    *hookSize = 14;
    
    // Allocate trampoline memory near the original function
    PVOID trampoline = VirtualAlloc(nullptr, 64,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    
    if (!trampoline) return nullptr;
    
    // Copy original bytes
    memcpy(trampoline, originalFunction, *hookSize);
    
    // Add jump back to original function + hookSize
    BYTE* trampolineBytes = static_cast<BYTE*>(trampoline);
    trampolineBytes[*hookSize] = 0x48; // mov rax, address
    trampolineBytes[*hookSize + 1] = 0xB8;
    *reinterpret_cast<ULONG_PTR*>(&trampolineBytes[*hookSize + 2]) = 
        reinterpret_cast<ULONG_PTR>(originalFunction) + *hookSize;
    trampolineBytes[*hookSize + 10] = 0xFF; // jmp rax
    trampolineBytes[*hookSize + 11] = 0xE0;
    
    // Flush cache
    FlushInstructionCache(GetCurrentProcess(), trampoline, 64);
    
    return trampoline;
#else
    // x86 requires 5 bytes for a relative jump
    *hookSize = 5;
    
    PVOID trampoline = VirtualAlloc(nullptr, 32,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    
    if (!trampoline) return nullptr;
    
    // Copy original bytes
    memcpy(trampoline, originalFunction, *hookSize);
    
    // Add jump back
    BYTE* trampolineBytes = static_cast<BYTE*>(trampoline);
    trampolineBytes[*hookSize] = 0xE9; // jmp relative
    DWORD relativeOffset = (reinterpret_cast<DWORD>(originalFunction) + *hookSize) - 
                          (reinterpret_cast<DWORD>(trampoline) + *hookSize + 5);
    *reinterpret_cast<DWORD*>(&trampolineBytes[*hookSize + 1]) = relativeOffset;
    
    FlushInstructionCache(GetCurrentProcess(), trampoline, 32);
    
    return trampoline;
#endif
}

// Install function hook
BOOL InstallFunctionHook(PSSDM_HOOK_CONTEXT context, 
                        PVOID originalFunction, 
                        PVOID hookFunction, 
                        const char* functionName) {
    
    if (!originalFunction || !hookFunction) {
        return FALSE;
    }
    
    // Create trampoline
    SIZE_T hookSize = 0;
    PVOID trampoline = CreateTrampoline(originalFunction, hookFunction, &hookSize);
    if (!trampoline) {
        return FALSE;
    }
    
    // Disable memory protection
    DWORD oldProtect = 0;
    if (!DisableMemoryProtection(originalFunction, hookSize, &oldProtect)) {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        return FALSE;
    }
    
    // Write hook
#ifdef _WIN64
    // x64: mov rax, hookFunction; jmp rax
    BYTE hookBytes[14] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, hookFunction
        0xFF, 0xE0                                                  // jmp rax
    };
    *reinterpret_cast<ULONG_PTR*>(&hookBytes[2]) = reinterpret_cast<ULONG_PTR>(hookFunction);
#else
    // x86: jmp relative to hookFunction
    BYTE hookBytes[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 }; // jmp relative
    DWORD relativeOffset = reinterpret_cast<DWORD>(hookFunction) - 
                          (reinterpret_cast<DWORD>(originalFunction) + 5);
    *reinterpret_cast<DWORD*>(&hookBytes[1]) = relativeOffset;
#endif
    
    memcpy(originalFunction, hookBytes, hookSize);
    
    // Restore protection
    RestoreMemoryProtection(originalFunction, hookSize, oldProtect);
    
    // Flush cache
    FlushInstructionCache(GetCurrentProcess(), originalFunction, hookSize);
    
    // Update context
    context->OriginalFunction = reinterpret_cast<ULONG_PTR>(originalFunction);
    context->HookFunction = reinterpret_cast<ULONG_PTR>(hookFunction);
    context->Trampoline = reinterpret_cast<ULONG_PTR>(trampoline);
    context->HookSize = hookSize;
    context->Protection = oldProtect;
    context->IsActive = TRUE;
    strcpy_s(context->FunctionName, functionName);
    
    SSDM_LOG("Hook installed for %s: 0x%p -> 0x%p", 
        functionName, originalFunction, hookFunction);
    
    return TRUE;
}

// Remove function hook
BOOL RemoveFunctionHook(PSSDM_HOOK_CONTEXT context) {
    if (!context->IsActive) {
        return TRUE;
    }
    
    PVOID originalFunction = reinterpret_cast<PVOID>(context->OriginalFunction);
    
    // Disable protection
    DWORD oldProtect = 0;
    if (!DisableMemoryProtection(originalFunction, context->HookSize, &oldProtect)) {
        return FALSE;
    }
    
    // Restore original bytes from trampoline
    memcpy(originalFunction, reinterpret_cast<PVOID>(context->Trampoline), context->HookSize);
    
    // Restore protection
    RestoreMemoryProtection(originalFunction, context->HookSize, oldProtect);
    
    // Flush cache
    FlushInstructionCache(GetCurrentProcess(), originalFunction, context->HookSize);
    
    // Free trampoline
    if (context->Trampoline) {
        VirtualFree(reinterpret_cast<PVOID>(context->Trampoline), 0, MEM_RELEASE);
    }
    
    // Reset context
    memset(context, 0, sizeof(SSDM_HOOK_CONTEXT));
    
    SSDM_LOG("Hook removed");
    return TRUE;
}

// ======================================================================
// 7. HOOKED FUNCTIONS
// ======================================================================

// Hooked LdrLoadDll
NTSTATUS NTAPI HookedLdrLoadDll(
    PWSTR SearchPath,
    PULONG LoadFlags,
    PUNICODE_STRING Name,
    PVOID* BaseAddress
) {
    EnterCriticalSection(&g_CriticalSection);
    
    SSDM_LOG("LdrLoadDll called for: %ws", Name ? Name->Buffer : L"Unknown");
    
    // Execute shellcode if available
    if (g_ShellcodeInfo.Buffer && g_ShellcodeInfo.IsExecutable) {
        SSDM_LOG("Executing shellcode from loader hook");
        
        // Create thread to execute shellcode
        HANDLE hThread = CreateThread(
            nullptr,
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(g_ShellcodeInfo.EntryPoint),
            nullptr,
            0,
            nullptr
        );
        
        if (hThread) {
            // Wait for shellcode completion
            WaitForSingleObject(hThread, 2000);
            CloseHandle(hThread);
            SSDM_LOG("Shellcode execution completed");
        }
    }
    
    // Call original function through trampoline
    NTSTATUS status = STATUS_SUCCESS;
    if (reinterpret_cast<PVOID>(g_LdrLoadDllHook.Trampoline)) {
        _LdrLoadDll originalFunc = reinterpret_cast<_LdrLoadDll>(
            reinterpret_cast<PVOID>(g_LdrLoadDllHook.Trampoline));
        status = originalFunc(SearchPath, LoadFlags, Name, BaseAddress);
    }
    
    // Post-load processing
    if (NT_SUCCESS(status) && BaseAddress && *BaseAddress) {
        SSDM_LOG("DLL loaded at: 0x%p", *BaseAddress);
    }
    
    LeaveCriticalSection(&g_CriticalSection);
    return status;
}

// Hooked NtCreateSection
NTSTATUS NTAPI HookedNtCreateSection(
    PHANDLE SectionHandle,
    ULONG DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG PageAttributess,
    ULONG SectionAttributes,
    HANDLE FileHandle
) {
    SSDM_LOG("NtCreateSection called");
    
    // Monitor section creation for shellcode patterns
    if (MaximumSize && MaximumSize->QuadPart > 0) {
        SSDM_LOG("Section size: %lld bytes", MaximumSize->QuadPart);
        
        // Check for suspicious sizes or attributes
        if ((SectionAttributes & SEC_IMAGE) == 0 && 
            (DesiredAccess & SECTION_MAP_EXECUTE)) {
            SSDM_LOG("Suspicious executable section without SEC_IMAGE flag");
        }
    }
    
    // Call original function
    if (reinterpret_cast<PVOID>(g_NtCreateSectionHook.Trampoline)) {
        _NtCreateSection originalFunc = reinterpret_cast<_NtCreateSection>(
            reinterpret_cast<PVOID>(g_NtCreateSectionHook.Trampoline));
        return originalFunc(SectionHandle, DesiredAccess, ObjectAttributes,
            MaximumSize, PageAttributess, SectionAttributes, FileHandle);
    }
    
    return STATUS_UNSUCCESSFUL;
}

// ======================================================================
// 8. SSDM INITIALIZATION AND MANAGEMENT
// ======================================================================

// Initialize SSDM framework
BOOL InitializeSSDM() {
    SSDM_LOG("Initializing SSDM Framework v%d", SSDM_HOOK_VERSION);
    
    // Initialize critical section
    InitializeCriticalSection(&g_CriticalSection);
    
    // Prepare shellcode
    if (!PrepareShellcode()) {
        SSDM_LOG("Warning: Failed to prepare shellcode");
    }
    
    // Get function addresses
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        SSDM_LOG("Failed to get ntdll handle");
        return FALSE;
    }
    
    PVOID ldrLoadDll = GetProcAddress(ntdll, "LdrLoadDll");
    PVOID ntCreateSection = GetProcAddress(ntdll, "NtCreateSection");
    
    if (!ldrLoadDll || !ntCreateSection) {
        SSDM_LOG("Failed to get function addresses");
        return FALSE;
    }
    
    // Install hooks
    BOOL hooksInstalled = TRUE;
    
    if (!InstallFunctionHook(&g_LdrLoadDllHook, 
                            ldrLoadDll, 
                            reinterpret_cast<PVOID>(HookedLdrLoadDll),
                            "LdrLoadDll")) {
        SSDM_LOG("Failed to install LdrLoadDll hook");
        hooksInstalled = FALSE;
    }
    
    if (!InstallFunctionHook(&g_NtCreateSectionHook,
                            ntCreateSection,
                            reinterpret_cast<PVOID>(HookedNtCreateSection),
                            "NtCreateSection")) {
        SSDM_LOG("Failed to install NtCreateSection hook");
        hooksInstalled = FALSE;
    }
    
    if (hooksInstalled) {
        SSDM_LOG("SSDM Framework initialized successfully");
    }
    
    return hooksInstalled;
}

// Cleanup SSDM framework
VOID CleanupSSDM() {
    SSDM_LOG("Cleaning up SSDM Framework");
    
    EnterCriticalSection(&g_CriticalSection);
    
    // Remove hooks
    RemoveFunctionHook(&g_LdrLoadDllHook);
    RemoveFunctionHook(&g_NtCreateSectionHook);
    
    // Free shellcode memory
    if (g_ShellcodeInfo.Buffer) {
        VirtualFree(g_ShellcodeInfo.Buffer, 0, MEM_RELEASE);
        memset(&g_ShellcodeInfo, 0, sizeof(SSDM_SHELLCODE_INFO));
    }
    
    LeaveCriticalSection(&g_CriticalSection);
    DeleteCriticalSection(&g_CriticalSection);
    
    SSDM_LOG("SSDM Framework cleaned up");
}

// Test the SSDM hooks
VOID TestSSDMHooks() {
    SSDM_LOG("Testing SSDM hooks...");
    
    // Test by loading a DLL (will trigger our hook)
    HMODULE hModule = LoadLibraryA("kernel32.dll");
    if (hModule) {
        SSDM_LOG("Test DLL loaded successfully");
        FreeLibrary(hModule);
    }
    
    // Test section creation
    HANDLE sectionHandle = nullptr;
    LARGE_INTEGER sectionSize = { .QuadPart = 4096 };
    
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    _NtCreateSection NtCreateSection = (_NtCreateSection)
        GetProcAddress(ntdll, "NtCreateSection");
    
    if (NtCreateSection) {
        NTSTATUS status = NtCreateSection(
            &sectionHandle,
            SECTION_ALL_ACCESS,
            nullptr,
            &sectionSize,
            PAGE_EXECUTE_READWRITE,
            SEC_COMMIT,
            nullptr
        );
        
        if (NT_SUCCESS(status)) {
            SSDM_LOG("Test section created successfully");
            CloseHandle(sectionHandle);
        }
    }
    
    SSDM_LOG("SSDM test completed");
}

// Display SSDM status
VOID DisplaySSDMStatus() {
    printf("\n=== SSDM STATUS ===\n");
    printf("Framework Version: 0x%X\n", SSDM_HOOK_VERSION);
    printf("\nActive Hooks:\n");
    
    if (g_LdrLoadDllHook.IsActive) {
        printf("  LdrLoadDll: ACTIVE (0x%p -> 0x%p)\n", 
            g_LdrLoadDllHook.OriginalFunction,
            g_LdrLoadDllHook.HookFunction);
    } else {
        printf("  LdrLoadDll: INACTIVE\n");
    }
    
    if (g_NtCreateSectionHook.IsActive) {
        printf("  NtCreateSection: ACTIVE (0x%p -> 0x%p)\n",
            g_NtCreateSectionHook.OriginalFunction,
            g_NtCreateSectionHook.HookFunction);
    } else {
        printf("  NtCreateSection: INACTIVE\n");
    }
    
    printf("\nShellcode Info:\n");
    if (g_ShellcodeInfo.Buffer) {
        printf("  Buffer: 0x%p\n", g_ShellcodeInfo.Buffer);
        printf("  Size: %zu bytes\n", g_ShellcodeInfo.Size);
        printf("  Executable: %s\n", g_ShellcodeInfo.IsExecutable ? "YES" : "NO");
    } else {
        printf("  No shellcode loaded\n");
    }
    
    printf("===================\n");
}

// ======================================================================
// 9. MAIN FUNCTION
// ======================================================================

int main() {
    printf("========================================\n");
    printf("   SSDM Loader Hook Implementation\n");
    printf("   Educational Research Tool\n");
    printf("========================================\n\n");
    
    // Check system architecture
#ifdef _WIN64
    printf("Running in 64-bit mode\n");
#else
    printf("Running in 32-bit mode\n");
#endif
    
    printf("\n[1] Initializing SSDM Framework...\n");
    if (!InitializeSSDM()) {
        printf("Failed to initialize SSDM Framework\n");
        return 1;
    }
    
    printf("\n[2] Displaying SSDM Status...\n");
    DisplaySSDMStatus();
    
    printf("\n[3] Testing SSDM Hooks...\n");
    TestSSDMHooks();
    
    printf("\n[4] Interactive Menu\n");
    printf("Press 's' to show status\n");
    printf("Press 't' to test hooks\n");
    printf("Press 'c' to cleanup and exit\n");
    printf("Press any other key to exit\n");
    
    // Simple interactive loop
    while (true) {
        char input = _getch();
        
        switch (tolower(input)) {
            case 's':
                DisplaySSDMStatus();
                break;
                
            case 't':
                TestSSDMHooks();
                break;
                
            case 'c':
                CleanupSSDM();
                printf("\nSSDM Framework cleaned up. Exiting...\n");
                return 0;
                
            default:
                CleanupSSDM();
                printf("\nExiting...\n");
                return 0;
        }
        
        printf("\nCommand executed. Press another key or 'c' to cleanup and exit\n");
    }
    
    return 0;
}

// ======================================================================
// 10. COMPILATION NOTES
// ======================================================================
/*
Compilation instructions:

For 64-bit:
    cl /EHsc /Zi /std:c++17 /Fe:ssdm_hook.exe ssdm_hook.cpp /link /DYNAMICBASE:NO

For 32-bit:
    cl /EHsc /Zi /std:c++17 /Fe:ssdm_hook_x86.exe ssdm_hook.cpp /link /DYNAMICBASE:NO

Important notes:
1. This code is for EDUCATIONAL PURPOSES ONLY
2. Requires Administrator privileges to modify kernel functions
3. May trigger antivirus/EDR systems
4. Test in isolated virtual machine only
5. Not production-ready - lacks error handling and stealth features

Security considerations:
- Hooking kernel functions can cause system instability
- PatchGuard will detect and crash the system on x64
- Use only for defensive security research
*/
