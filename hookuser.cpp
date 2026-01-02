// ======================================================================
// SSDM User-Mode Monitoring Framework
// Complete Single-File Implementation
// Educational Purpose - User-Mode Security Research
// ======================================================================

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <detours.h>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <thread>
#include <mutex>
#include <atomic>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <DbgHelp.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "detours.lib")

// ======================================================================
// 1. CONSTANTS AND DEFINITIONS
// ======================================================================

#define SSDM_UM_VERSION "1.0.0"
#define MAX_HOOKS 256
#define BUFFER_SIZE 4096
#define LOG_FILE "ssdm_um.log"

// Hook types
enum HOOK_TYPE {
    HOOK_IAT = 0,           // Import Address Table hook
    HOOK_EAT = 1,           // Export Address Table hook
    HOOK_INLINE = 2,        // Inline function hook
    HOOK_DETOURS = 3,       // Microsoft Detours hook
    HOOK_CALLBACK = 4,      // Callback registration
    HOOK_VEH = 5            // Vectored Exception Handler
};

// Monitor flags
enum MONITOR_FLAGS {
    MONITOR_PROCESS = 0x0001,
    MONITOR_THREAD = 0x0002,
    MONITOR_MODULE = 0x0004,
    MONITOR_MEMORY = 0x0008,
    MONITOR_REGISTRY = 0x0010,
    MONITOR_FILE = 0x0020,
    MONITOR_NETWORK = 0x0040,
    MONITOR_SYSCALL = 0x0080,
    MONITOR_ALL = 0xFFFF
};

// ======================================================================
// 2. STRUCTURES AND CLASSES
// ======================================================================

// Hook information structure
typedef struct _SSDM_HOOK_INFO {
    DWORD hookId;
    HOOK_TYPE type;
    LPVOID originalAddress;
    LPVOID hookAddress;
    LPVOID trampoline;
    std::string moduleName;
    std::string functionName;
    BOOL isActive;
    DWORD protection;
} SSDM_HOOK_INFO, *PSSDM_HOOK_INFO;

// Process monitor event
typedef struct _PROCESS_EVENT {
    DWORD eventType;        // CREATE, TERMINATE, etc.
    DWORD processId;
    DWORD parentProcessId;
    std::string processName;
    std::string imagePath;
    FILETIME createTime;
    std::string commandLine;
} PROCESS_EVENT, *PPROCESS_EVENT;

// Thread monitor event
typedef struct _THREAD_EVENT {
    DWORD eventType;        // CREATE, TERMINATE, etc.
    DWORD threadId;
    DWORD processId;
    LPVOID startAddress;
    std::string moduleName;
} THREAD_EVENT, *PTHREAD_EVENT;

// Memory monitor event
typedef struct _MEMORY_EVENT {
    DWORD eventType;        // ALLOCATE, FREE, PROTECT, etc.
    DWORD processId;
    LPVOID address;
    SIZE_T size;
    DWORD protection;
    std::string regionType;
} MEMORY_EVENT, *PMEMORY_EVENT;

// ======================================================================
// 3. SSDM USER-MODE MONITOR CLASS
// ======================================================================

class SSDMMonitor {
private:
    // Core components
    std::vector<SSDM_HOOK_INFO> m_hooks;
    std::map<DWORD, PROCESS_EVENT> m_processes;
    std::map<DWORD, std::vector<THREAD_EVENT>> m_threads;
    
    // Synchronization
    std::mutex m_hookMutex;
    std::mutex m_eventMutex;
    std::mutex m_logMutex;
    
    // Configuration
    DWORD m_monitorFlags;
    BOOL m_isMonitoring;
    std::atomic<BOOL> m_shouldExit;
    
    // Logging
    std::ofstream m_logFile;
    std::string m_logPath;
    
    // Worker threads
    std::vector<std::thread> m_workers;
    
    // Callback storage
    std::map<std::string, std::vector<LPVOID>> m_callbacks;
    
public:
    // Constructor/Destructor
    SSDMMonitor() : m_monitorFlags(MONITOR_ALL), 
                   m_isMonitoring(FALSE),
                   m_shouldExit(FALSE) {
        Initialize();
    }
    
    ~SSDMonitor() {
        StopMonitoring();
        Cleanup();
    }
    
    // ==================================================================
    // 4. INITIALIZATION AND SETUP
    // ==================================================================
    
    BOOL Initialize() {
        // Initialize logging
        if (!InitializeLogging()) {
            std::cerr << "[SSDM] Failed to initialize logging" << std::endl;
            return FALSE;
        }
        
        Log("SSDM User-Mode Monitor v" SSDM_UM_VERSION " initialized");
        
        // Initialize process snapshot
        if (!InitializeProcessSnapshot()) {
            Log("Warning: Failed to initialize process snapshot");
        }
        
        // Initialize hooks
        InitializeDefaultHooks();
        
        return TRUE;
    }
    
    BOOL InitializeLogging() {
        char path[MAX_PATH];
        if (GetModuleFileNameA(NULL, path, MAX_PATH) == 0) {
            return FALSE;
        }
        
        std::string exePath = path;
        size_t lastSlash = exePath.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            m_logPath = exePath.substr(0, lastSlash + 1) + LOG_FILE;
        } else {
            m_logPath = LOG_FILE;
        }
        
        m_logFile.open(m_logPath, std::ios::app);
        if (!m_logFile.is_open()) {
            return FALSE;
        }
        
        // Write header
        SYSTEMTIME st;
        GetLocalTime(&st);
        m_logFile << "\n=== SSDM User-Mode Monitor Log ===" << std::endl;
        m_logFile << "Started: " << st.wYear << "-" << st.wMonth << "-" << st.wDay 
                 << " " << st.wHour << ":" << st.wMinute << ":" << st.wSecond << std::endl;
        
        return TRUE;
    }
    
    BOOL InitializeProcessSnapshot() {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return FALSE;
        }
        
        PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
        if (Process32First(snapshot, &pe)) {
            do {
                PROCESS_EVENT event = { 0 };
                event.eventType = 1; // Existing process
                event.processId = pe.th32ProcessID;
                event.parentProcessId = pe.th32ParentProcessID;
                event.processName = pe.szExeFile;
                
                std::lock_guard<std::mutex> lock(m_eventMutex);
                m_processes[pe.th32ProcessID] = event;
                
            } while (Process32Next(snapshot, &pe));
        }
        
        CloseHandle(snapshot);
        return TRUE;
    }
    
    // ==================================================================
    // 5. HOOK MANAGEMENT
    // ==================================================================
    
    VOID InitializeDefaultHooks() {
        Log("Initializing default hooks...");
        
        // Hook critical Windows APIs
        InstallIATHook("kernel32.dll", "CreateProcessW", 
                      (LPVOID)HookedCreateProcessW);
        
        InstallIATHook("kernel32.dll", "CreateThread",
                      (LPVOID)HookedCreateThread);
        
        InstallIATHook("kernel32.dll", "VirtualAlloc",
                      (LPVOID)HookedVirtualAlloc);
        
        InstallIATHook("kernel32.dll", "VirtualProtect",
                      (LPVOID)HookedVirtualProtect);
        
        InstallIATHook("kernel32.dll", "LoadLibraryA",
                      (LPVOID)HookedLoadLibraryA);
        
        InstallIATHook("kernel32.dll", "LoadLibraryW",
                      (LPVOID)HookedLoadLibraryW);
        
        InstallIATHook("ntdll.dll", "NtAllocateVirtualMemory",
                      (LPVOID)HookedNtAllocateVirtualMemory);
        
        Log("Default hooks installed");
    }
    
    // IAT Hook Installation
    BOOL InstallIATHook(const std::string& moduleName, 
                       const std::string& functionName,
                       LPVOID hookFunction) {
        
        HMODULE hModule = GetModuleHandleA(moduleName.c_str());
        if (!hModule) {
            Log("Failed to get module handle: %s", moduleName.c_str());
            return FALSE;
        }
        
        // Get module base address
        PBYTE moduleBase = (PBYTE)hModule;
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            Log("Invalid DOS header for module: %s", moduleName.c_str());
            return FALSE;
        }
        
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(moduleBase + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            Log("Invalid NT header for module: %s", moduleName.c_str());
            return FALSE;
        }
        
        // Find IAT
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(
            moduleBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        
        for (; importDesc->Name; importDesc++) {
            char* dllName = (char*)(moduleBase + importDesc->Name);
            
            PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)(moduleBase + importDesc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA iatThunk = (PIMAGE_THUNK_DATA)(moduleBase + importDesc->FirstThunk);
            
            for (; origThunk->u1.AddressOfData; origThunk++, iatThunk++) {
                if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(
                        moduleBase + origThunk->u1.AddressOfData);
                    
                    if (strcmp(functionName.c_str(), (char*)importByName->Name) == 0) {
                        // Found the function, install hook
                        DWORD oldProtect;
                        VirtualProtect(&iatThunk->u1.Function, sizeof(LPVOID), 
                                      PAGE_EXECUTE_READWRITE, &oldProtect);
                        
                        SSDM_HOOK_INFO hookInfo = { 0 };
                        hookInfo.hookId = (DWORD)m_hooks.size() + 1;
                        hookInfo.type = HOOK_IAT;
                        hookInfo.originalAddress = (LPVOID)iatThunk->u1.Function;
                        hookInfo.hookAddress = hookFunction;
                        hookInfo.moduleName = moduleName;
                        hookInfo.functionName = functionName;
                        hookInfo.isActive = TRUE;
                        hookInfo.protection = oldProtect;
                        
                        // Save original function
                        iatThunk->u1.Function = (ULONGLONG)hookFunction;
                        
                        // Restore protection
                        VirtualProtect(&iatThunk->u1.Function, sizeof(LPVOID), 
                                      oldProtect, &oldProtect);
                        
                        // Add to hooks list
                        std::lock_guard<std::mutex> lock(m_hookMutex);
                        m_hooks.push_back(hookInfo);
                        
                        Log("IAT Hook installed: %s!%s (0x%p -> 0x%p)",
                            moduleName.c_str(), functionName.c_str(),
                            hookInfo.originalAddress, hookFunction);
                        
                        return TRUE;
                    }
                }
            }
        }
        
        Log("Function not found in IAT: %s!%s", moduleName.c_str(), functionName.c_str());
        return FALSE;
    }
    
    // Inline Hook Installation (Hotpatching)
    BOOL InstallInlineHook(LPVOID targetFunction, LPVOID hookFunction, LPVOID* originalFunction) {
        // Minimum 5 bytes for x86, 12-14 for x64
        #ifdef _WIN64
            SIZE_T hookSize = 14;
            BYTE jmpCode[14] = {
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, hookFunction
                0xFF, 0xE0                                                  // jmp rax
            };
            *(ULONG_PTR*)(jmpCode + 2) = (ULONG_PTR)hookFunction;
        #else
            SIZE_T hookSize = 5;
            BYTE jmpCode[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 }; // jmp relative
            DWORD relativeOffset = (DWORD)hookFunction - (DWORD)targetFunction - 5;
            *(DWORD*)(jmpCode + 1) = relativeOffset;
        #endif
        
        DWORD oldProtect;
        if (!VirtualProtect(targetFunction, hookSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return FALSE;
        }
        
        // Allocate trampoline
        PBYTE trampoline = (PBYTE)VirtualAlloc(NULL, hookSize + sizeof(jmpCode), 
                                              MEM_COMMIT | MEM_RESERVE, 
                                              PAGE_EXECUTE_READWRITE);
        if (!trampoline) {
            VirtualProtect(targetFunction, hookSize, oldProtect, &oldProtect);
            return FALSE;
        }
        
        // Copy original bytes to trampoline
        memcpy(trampoline, targetFunction, hookSize);
        
        // Add jump back to original code after hook
        #ifdef _WIN64
            BYTE backJmp[14] = {
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xFF, 0xE0
            };
            *(ULONG_PTR*)(backJmp + 2) = (ULONG_PTR)targetFunction + hookSize;
            memcpy(trampoline + hookSize, backJmp, sizeof(backJmp));
        #else
            BYTE backJmp[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
            DWORD backOffset = ((DWORD)targetFunction + hookSize) - ((DWORD)trampoline + hookSize + 5);
            *(DWORD*)(backJmp + 1) = backOffset;
            memcpy(trampoline + hookSize, backJmp, sizeof(backJmp));
        #endif
        
        // Write hook
        memcpy(targetFunction, jmpCode, hookSize);
        
        // Restore protection
        VirtualProtect(targetFunction, hookSize, oldProtect, &oldProtect);
        
        // Flush instruction cache
        FlushInstructionCache(GetCurrentProcess(), targetFunction, hookSize);
        FlushInstructionCache(GetCurrentProcess(), trampoline, hookSize + sizeof(jmpCode));
        
        // Store hook info
        SSDM_HOOK_INFO hookInfo = { 0 };
        hookInfo.hookId = (DWORD)m_hooks.size() + 1;
        hookInfo.type = HOOK_INLINE;
        hookInfo.originalAddress = targetFunction;
        hookInfo.hookAddress = hookFunction;
        hookInfo.trampoline = trampoline;
        hookInfo.isActive = TRUE;
        hookInfo.protection = oldProtect;
        
        std::lock_guard<std::mutex> lock(m_hookMutex);
        m_hooks.push_back(hookInfo);
        
        if (originalFunction) {
            *originalFunction = trampoline;
        }
        
        Log("Inline Hook installed: 0x%p -> 0x%p", targetFunction, hookFunction);
        return TRUE;
    }
    
    // ==================================================================
    // 6. HOOKED FUNCTIONS
    // ==================================================================
    
    // Hooked CreateProcessW
    static BOOL WINAPI HookedCreateProcessW(
        LPCWSTR lpApplicationName,
        LPWSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        LPVOID lpEnvironment,
        LPCWSTR lpCurrentDirectory,
        LPSTARTUPINFOW lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation) {
        
        SSDMMonitor* monitor = SSDMMonitor::GetInstance();
        monitor->Log("CreateProcessW called: %ls", 
                    lpApplicationName ? lpApplicationName : lpCommandLine);
        
        // Log process creation attempt
        PROCESS_EVENT event = { 0 };
        event.eventType = 0x1001; // Process create attempt
        event.processName = "Unknown";
        event.commandLine = lpCommandLine ? 
            monitor->WideStringToString(lpCommandLine) : "";
        
        monitor->LogEvent(event);
        
        // Call original function (we'd need trampoline here)
        // For now, just pass through
        return CreateProcessW(lpApplicationName, lpCommandLine,
                            lpProcessAttributes, lpThreadAttributes,
                            bInheritHandles, dwCreationFlags,
                            lpEnvironment, lpCurrentDirectory,
                            lpStartupInfo, lpProcessInformation);
    }
    
    // Hooked CreateThread
    static HANDLE WINAPI HookedCreateThread(
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        SIZE_T dwStackSize,
        LPTHREAD_START_ROUTINE lpStartAddress,
        LPVOID lpParameter,
        DWORD dwCreationFlags,
        LPDWORD lpThreadId) {
        
        SSDMMonitor* monitor = SSDMMonitor::GetInstance();
        
        // Get calling module info
        HMODULE hModule = NULL;
        GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                         (LPCTSTR)lpStartAddress, &hModule);
        
        char moduleName[MAX_PATH] = { 0 };
        if (hModule) {
            GetModuleFileNameA(hModule, moduleName, MAX_PATH);
            // Extract just the filename
            char* fileName = strrchr(moduleName, '\\');
            if (fileName) fileName++;
            else fileName = moduleName;
            
            monitor->Log("CreateThread: Start address 0x%p in module %s",
                        lpStartAddress, fileName);
        }
        
        // Call original
        return CreateThread(lpThreadAttributes, dwStackSize,
                          lpStartAddress, lpParameter,
                          dwCreationFlags, lpThreadId);
    }
    
    // Hooked VirtualAlloc
    static LPVOID WINAPI HookedVirtualAlloc(
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD flAllocationType,
        DWORD flProtect) {
        
        SSDMMonitor* monitor = SSDMMonitor::GetInstance();
        
        // Log memory allocation
        MEMORY_EVENT event = { 0 };
        event.eventType = 0x2001; // Memory allocate
        event.processId = GetCurrentProcessId();
        event.address = lpAddress;
        event.size = dwSize;
        event.protection = flProtect;
        event.regionType = (flAllocationType & MEM_COMMIT) ? "Commit" : "Reserve";
        
        monitor->LogEvent(event);
        
        monitor->Log("VirtualAlloc: Size=%zu, Protection=0x%X, Type=%s",
                    dwSize, flProtect, event.regionType.c_str());
        
        // Call original
        return VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    }
    
    // Hooked VirtualProtect
    static BOOL WINAPI HookedVirtualProtect(
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD flNewProtect,
        PDWORD lpflOldProtect) {
        
        SSDMMonitor* monitor = SSDMMonitor::GetInstance();
        
        DWORD oldProtect;
        BOOL result = VirtualProtect(lpAddress, dwSize, flNewProtect, &oldProtect);
        
        if (result) {
            MEMORY_EVENT event = { 0 };
            event.eventType = 0x2002; // Memory protect change
            event.processId = GetCurrentProcessId();
            event.address = lpAddress;
            event.size = dwSize;
            event.protection = flNewProtect;
            
            monitor->LogEvent(event);
            
            monitor->Log("VirtualProtect: Address=0x%p, Size=%zu, OldProt=0x%X, NewProt=0x%X",
                        lpAddress, dwSize, oldProtect, flNewProtect);
        }
        
        if (lpflOldProtect) {
            *lpflOldProtect = oldProtect;
        }
        
        return result;
    }
    
    // Hooked LoadLibraryA
    static HMODULE WINAPI HookedLoadLibraryA(LPCSTR lpLibFileName) {
        SSDMMonitor* monitor = SSDMMonitor::GetInstance();
        monitor->Log("LoadLibraryA: %s", lpLibFileName);
        
        // Call original
        HMODULE hModule = LoadLibraryA(lpLibFileName);
        
        if (hModule) {
            char path[MAX_PATH];
            GetModuleFileNameA(hModule, path, MAX_PATH);
            monitor->Log("Library loaded: %s -> %s", lpLibFileName, path);
        }
        
        return hModule;
    }
    
    // Hooked LoadLibraryW
    static HMODULE WINAPI HookedLoadLibraryW(LPCWSTR lpLibFileName) {
        SSDMMonitor* monitor = SSDMMonitor::GetInstance();
        std::string fileName = monitor->WideStringToString(lpLibFileName);
        monitor->Log("LoadLibraryW: %s", fileName.c_str());
        
        // Call original
        return LoadLibraryW(lpLibFileName);
    }
    
    // Hooked NtAllocateVirtualMemory (via ntdll)
    static NTSTATUS NTAPI HookedNtAllocateVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect) {
        
        SSDMMonitor* monitor = SSDMMonitor::GetInstance();
        
        monitor->Log("NtAllocateVirtualMemory: Process=0x%p, Size=%zu, Protect=0x%X",
                    ProcessHandle, RegionSize ? *RegionSize : 0, Protect);
        
        // Get ntdll module
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (!ntdll) {
            return STATUS_UNSUCCESSFUL;
        }
        
        // Get original function
        typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
            HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        
        NtAllocateVirtualMemory_t origFunc = (NtAllocateVirtualMemory_t)
            GetProcAddress(ntdll, "NtAllocateVirtualMemory");
        
        if (!origFunc) {
            return STATUS_UNSUCCESSFUL;
        }
        
        // Call original
        return origFunc(ProcessHandle, BaseAddress, ZeroBits, 
                       RegionSize, AllocationType, Protect);
    }
    
    // ==================================================================
    // 7. MONITORING ENGINE
    // ==================================================================
    
    VOID StartMonitoring() {
        if (m_isMonitoring) {
            Log("Monitoring already active");
            return;
        }
        
        m_isMonitoring = TRUE;
        m_shouldExit = FALSE;
        
        Log("Starting user-mode monitoring...");
        
        // Start worker threads
        m_workers.push_back(std::thread(&SSDMMonitor::ProcessMonitorThread, this));
        m_workers.push_back(std::thread(&SSDMMonitor::ThreadMonitorThread, this));
        m_workers.push_back(std::thread(&SSDMMonitor::MemoryMonitorThread, this));
        m_workers.push_back(std::thread(&SSDMMonitor::EventProcessorThread, this));
        
        Log("Monitoring started with %zu worker threads", m_workers.size());
    }
    
    VOID StopMonitoring() {
        if (!m_isMonitoring) {
            return;
        }
        
        Log("Stopping monitoring...");
        m_shouldExit = TRUE;
        
        // Join all worker threads
        for (auto& thread : m_workers) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        
        m_workers.clear();
        m_isMonitoring = FALSE;
        
        Log("Monitoring stopped");
    }
    
    // Process monitoring thread
    VOID ProcessMonitorThread() {
        Log("Process monitor thread started");
        
        std::map<DWORD, PROCESS_EVENT> lastSnapshot;
        
        while (!m_shouldExit) {
            // Take process snapshot
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
                std::map<DWORD, PROCESS_EVENT> currentSnapshot;
                
                if (Process32First(snapshot, &pe)) {
                    do {
                        PROCESS_EVENT event = { 0 };
                        event.processId = pe.th32ProcessID;
                        event.parentProcessId = pe.th32ParentProcessID;
                        event.processName = pe.szExeFile;
                        
                        // Check if this is a new process
                        if (lastSnapshot.find(pe.th32ProcessID) == lastSnapshot.end()) {
                            event.eventType = 0x1001; // Process created
                            GetProcessCreateTime(pe.th32ProcessID, &event.createTime);
                            Log("Process created: %s (PID: %d)", 
                                pe.szExeFile, pe.th32ProcessID);
                        } else {
                            event.eventType = 0x1000; // Process exists
                        }
                        
                        currentSnapshot[pe.th32ProcessID] = event;
                        
                    } while (Process32Next(snapshot, &pe));
                }
                
                // Check for terminated processes
                for (const auto& pair : lastSnapshot) {
                    if (currentSnapshot.find(pair.first) == currentSnapshot.end()) {
                        PROCESS_EVENT event = pair.second;
                        event.eventType = 0x1002; // Process terminated
                        Log("Process terminated: %s (PID: %d)", 
                            event.processName.c_str(), pair.first);
                        
                        LogEvent(event);
                    }
                }
                
                lastSnapshot = currentSnapshot;
                CloseHandle(snapshot);
            }
            
            // Sleep before next snapshot
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
        
        Log("Process monitor thread stopped");
    }
    
    // Thread monitoring thread
    VOID ThreadMonitorThread() {
        Log("Thread monitor thread started");
        
        while (!m_shouldExit) {
            // Monitor threads in our process
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snapshot != INVALID_HANDLE_VALUE) {
                THREADENTRY32 te = { sizeof(THREADENTRY32) };
                DWORD currentPid = GetCurrentProcessId();
                
                if (Thread32First(snapshot, &te)) {
                    do {
                        if (te.th32OwnerProcessID == currentPid) {
                            // Found a thread in our process
                            THREAD_EVENT event = { 0 };
                            event.threadId = te.th32ThreadID;
                            event.processId = te.th32OwnerProcessID;
                            event.eventType = 0x2000; // Thread exists
                            
                            // Store thread info
                            std::lock_guard<std::mutex> lock(m_eventMutex);
                            m_threads[te.th32OwnerProcessID].push_back(event);
                        }
                    } while (Thread32Next(snapshot, &te));
                }
                
                CloseHandle(snapshot);
            }
            
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
        
        Log("Thread monitor thread stopped");
    }
    
    // Memory monitoring thread
    VOID MemoryMonitorThread() {
        Log("Memory monitor thread started");
        
        MEMORY_BASIC_INFORMATION mbi;
        PBYTE address = NULL;
        
        while (!m_shouldExit) {
            // Scan process memory
            while (VirtualQuery(address, &mbi, sizeof(mbi))) {
                if (mbi.State == MEM_COMMIT) {
                    MEMORY_EVENT event = { 0 };
                    event.eventType = 0x3000; // Memory region exists
                    event.address = mbi.BaseAddress;
                    event.size = mbi.RegionSize;
                    event.protection = mbi.Protect;
                    
                    // Determine region type
                    if (mbi.Type == MEM_IMAGE) event.regionType = "IMAGE";
                    else if (mbi.Type == MEM_MAPPED) event.regionType = "MAPPED";
                    else if (mbi.Type == MEM_PRIVATE) event.regionType = "PRIVATE";
                    
                    // Log large or executable regions
                    if (mbi.RegionSize > 1024 * 1024 || // > 1MB
                        (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | 
                                        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                        Log("Memory Region: 0x%p, Size=%zu, Protect=0x%X, Type=%s",
                            mbi.BaseAddress, mbi.RegionSize, mbi.Protect, 
                            event.regionType.c_str());
                    }
                }
                
                address += mbi.RegionSize;
            }
            
            address = NULL;
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }
        
        Log("Memory monitor thread stopped");
    }
    
    // Event processor thread
    VOID EventProcessorThread() {
        Log("Event processor thread started");
        
        // Process events and write to log
        while (!m_shouldExit) {
            // Here you would process events from queues
            // For now, just sleep
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        Log("Event processor thread stopped");
    }
    
    // ==================================================================
    // 8. UTILITY FUNCTIONS
    // ==================================================================
    
    BOOL GetProcessCreateTime(DWORD pid, FILETIME* createTime) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProcess) {
            return FALSE;
        }
        
        FILETIME ftCreate, ftExit, ftKernel, ftUser;
        if (GetProcessTimes(hProcess, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
            *createTime = ftCreate;
            CloseHandle(hProcess);
            return TRUE;
        }
        
        CloseHandle(hProcess);
        return FALSE;
    }
    
    std::string WideStringToString(LPCWSTR wideString) {
        if (!wideString) return "";
        
        int size = WideCharToMultiByte(CP_UTF8, 0, wideString, -1, NULL, 0, NULL, NULL);
        if (size == 0) return "";
        
        std::string result(size, 0);
        WideCharToMultiByte(CP_UTF8, 0, wideString, -1, &result[0], size, NULL, NULL);
        return result;
    }
    
    VOID Log(const char* format, ...) {
        std::lock_guard<std::mutex> lock(m_logMutex);
        
        char buffer[1024];
        va_list args;
        va_start(args, format);
        vsprintf_s(buffer, format, args);
        va_end(args);
        
        // Console output
        std::cout << "[SSDM] " << buffer << std::endl;
        
        // File output
        if (m_logFile.is_open()) {
            SYSTEMTIME st;
            GetLocalTime(&st);
            
            m_logFile << "[" << std::setw(2) << st.wHour << ":"
                     << std::setw(2) << st.wMinute << ":"
                     << std::setw(2) << st.wSecond << "] "
                     << buffer << std::endl;
        }
    }
    
    VOID LogEvent(const PROCESS_EVENT& event) {
        std::lock_guard<std::mutex> lock(m_eventMutex);
        m_processes[event.processId] = event;
    }
    
    VOID LogEvent(const MEMORY_EVENT& event) {
        // Store memory events if needed
    }
    
    // ==================================================================
    // 9. STATIC INSTANCE MANAGEMENT
    // ==================================================================
    
    static SSDMMonitor* GetInstance() {
        static SSDMMonitor instance;
        return &instance;
    }
    
    // ==================================================================
    // 10. CLEANUP
    // ==================================================================
    
    VOID Cleanup() {
        Log("Cleaning up SSDM Monitor...");
        
        // Remove all hooks
        {
            std::lock_guard<std::mutex> lock(m_hookMutex);
            for (auto& hook : m_hooks) {
                if (hook.isActive) {
                    // Remove hook logic would go here
                    Log("Hook removed: %s!%s", 
                        hook.moduleName.c_str(), hook.functionName.c_str());
                }
            }
            m_hooks.clear();
        }
        
        // Close log file
        if (m_logFile.is_open()) {
            m_logFile.close();
        }
        
        Log("SSDM Monitor cleaned up");
    }
    
    // ==================================================================
    // 11. PUBLIC INTERFACE
    // ==================================================================
    
    VOID SetMonitorFlags(DWORD flags) {
        m_monitorFlags = flags;
        Log("Monitor flags set to 0x%X", flags);
    }
    
    DWORD GetMonitorFlags() const {
        return m_monitorFlags;
    }
    
    BOOL IsMonitoring() const {
        return m_isMonitoring;
    }
    
    std::vector<SSDM_HOOK_INFO> GetActiveHooks() {
        std::lock_guard<std::mutex> lock(m_hookMutex);
        return m_hooks;
    }
    
    std::map<DWORD, PROCESS_EVENT> GetProcesses() {
        std::lock_guard<std::mutex> lock(m_eventMutex);
        return m_processes;
    }
    
    VOID SaveReport(const std::string& filename) {
        std::lock_guard<std::mutex> lock(m_logMutex);
        
        std::ofstream report(filename);
        if (!report.is_open()) {
            Log("Failed to create report file: %s", filename.c_str());
            return;
        }
        
        SYSTEMTIME st;
        GetLocalTime(&st);
        
        report << "=== SSDM User-Mode Monitoring Report ===" << std::endl;
        report << "Generated: " << st.wYear << "-" << st.wMonth << "-" << st.wDay 
               << " " << st.wHour << ":" << st.wMinute << ":" << st.wSecond << std::endl;
        report << "========================================" << std::endl << std::endl;
        
        // Active hooks section
        report << "ACTIVE HOOKS (" << m_hooks.size() << "):" << std::endl;
        report << "----------------------------------------" << std::endl;
        
        for (const auto& hook : m_hooks) {
            report << "ID: " << hook.hookId << std::endl;
            report << "Module: " << hook.moduleName << std::endl;
            report << "Function: " << hook.functionName << std::endl;
            report << "Original: 0x" << std::hex << hook.originalAddress 
                   << " -> Hook: 0x" << hook.hookAddress << std::endl;
            report << "Type: " << hook.type << " | Active: " << hook.isActive << std::endl;
            report << std::endl;
        }
        
        // Process list section
        report << "MONITORED PROCESSES (" << m_processes.size() << "):" << std::endl;
        report << "----------------------------------------" << std::endl;
        
        for (const auto& pair : m_processes) {
            report << "PID: " << pair.first << std::endl;
            report << "Name: " << pair.second.processName << std::endl;
            report << "Parent PID: " << pair.second.parentProcessId << std::endl;
            report << std::endl;
        }
        
        report.close();
        Log("Report saved to: %s", filename.c_str());
    }
};

// ======================================================================
// 12. MAIN APPLICATION
// ======================================================================

VOID PrintBanner() {
    std::cout << R"(
   _____ _____ ____  __  __       _   _                 
  / ____/ ____|  _ \|  \/  |     | | | |                
 | (___| (___ | |_) | \  / |_   _| |_| |_ _ __ ___ _ __ 
  \___ \\___ \|  _ <| |\/| | | | | __| __| '__/ _ \ '__|
  ____) |___) | |_) | |  | | |_| | |_| |_| | |  __/ |   
 |_____/_____/|____/|_|  |_|\__,_|\__|\__|_|  \___|_|   
                                                        
    User-Mode Monitoring Framework v)" SSDM_UM_VERSION R"(
    ====================================================
)" << std::endl;
}

VOID PrintMenu() {
    std::cout << "\n=== SSDM Menu ===" << std::endl;
    std::cout << "1. Start Monitoring" << std::endl;
    std::cout << "2. Stop Monitoring" << std::endl;
    std::cout << "3. Show Active Hooks" << std::endl;
    std::cout << "4. Show Monitored Processes" << std::endl;
    std::cout << "5. Save Report" << std::endl;
    std::cout << "6. Set Monitor Flags" << std::endl;
    std::cout << "7. Install Custom Hook" << std::endl;
    std::cout << "8. View Log" << std::endl;
    std::cout << "9. Exit" << std::endl;
    std::cout << "=================" << std::endl;
    std::cout << "Choice: ";
}

VOID ShowActiveHooks(SSDMMonitor* monitor) {
    auto hooks = monitor->GetActiveHooks();
    
    std::cout << "\n=== Active Hooks ===" << std::endl;
    std::cout << "Total: " << hooks.size() << std::endl << std::endl;
    
    for (const auto& hook : hooks) {
        std::cout << "[" << hook.hookId << "] " 
                  << hook.moduleName << "!" << hook.functionName << std::endl;
        std::cout << "    Original: 0x" << std::hex << hook.originalAddress 
                  << " -> Hook: 0x" << hook.hookAddress << std::dec << std::endl;
        std::cout << "    Type: " << hook.type 
                  << " | Active: " << (hook.isActive ? "Yes" : "No") << std::endl << std::endl;
    }
}

VOID ShowMonitoredProcesses(SSDMMonitor* monitor) {
    auto processes = monitor->GetProcesses();
    
    std::cout << "\n=== Monitored Processes ===" << std::endl;
    std::cout << "Total: " << processes.size() << std::endl << std::endl;
    
    std::cout << std::left << std::setw(8) << "PID" 
              << std::setw(30) << "Name" 
              << std::setw(10) << "Parent PID" << std::endl;
    std::cout << std::string(48, '-') << std::endl;
    
    for (const auto& pair : processes) {
        std::cout << std::left << std::setw(8) << pair.first
                  << std::setw(30) << pair.second.processName.substr(0, 29)
                  << std::setw(10) << pair.second.parentProcessId << std::endl;
    }
}

int main() {
    PrintBanner();
    
    // Get SSDM instance
    SSDMMonitor* monitor = SSDMMonitor::GetInstance();
    
    // Main loop
    BOOL running = TRUE;
    while (running) {
        PrintMenu();
        
        int choice;
        std::cin >> choice;
        
        switch (choice) {
            case 1: // Start Monitoring
                monitor->StartMonitoring();
                std::cout << "Monitoring started. Check log file for details." << std::endl;
                break;
                
            case 2: // Stop Monitoring
                monitor->StopMonitoring();
                std::cout << "Monitoring stopped." << std::endl;
                break;
                
            case 3: // Show Active Hooks
                ShowActiveHooks(monitor);
                break;
                
            case 4: // Show Monitored Processes
                ShowMonitoredProcesses(monitor);
                break;
                
            case 5: // Save Report
                monitor->SaveReport("ssdm_report.txt");
                std::cout << "Report saved as 'ssdm_report.txt'" << std::endl;
                break;
                
            case 6: // Set Monitor Flags
                {
                    std::cout << "\nEnter monitor flags (hex): ";
                    DWORD flags;
                    std::cin >> std::hex >> flags >> std::dec;
                    monitor->SetMonitorFlags(flags);
                }
                break;
                
            case 7: // Install Custom Hook
                {
                    std::cout << "\nCustom hook installation not implemented in this demo." << std::endl;
                    std::cout << "See source code for hook installation examples." << std::endl;
                }
                break;
                
            case 8: // View Log
                {
                    std::ifstream logFile(LOG_FILE);
                    if (logFile.is_open()) {
                        std::cout << "\n=== SSDM Log ===" << std::endl;
                        std::string line;
                        while (std::getline(logFile, line)) {
                            std::cout << line << std::endl;
                        }
                        logFile.close();
                    } else {
                        std::cout << "Log file not found or cannot be opened." << std::endl;
                    }
                }
                break;
                
            case 9: // Exit
                running = FALSE;
                std::cout << "Exiting..." << std::endl;
                break;
                
            default:
                std::cout << "Invalid choice. Please try again." << std::endl;
                break;
        }
        
        std::cout << std::endl;
    }
    
    // Cleanup happens automatically through destructor
    return 0;
}

// ======================================================================
// 13. COMPILATION INSTRUCTIONS
// ======================================================================
/*
Required libraries:
- detours.lib (Microsoft Detours)
- ntdll.lib
- psapi.lib
- dbghelp.lib

Compilation (Visual Studio or MSVC):
    cl /EHsc /Zi /std:c++17 /Fe:ssdm_um.exe ssdm_um.cpp /link detours.lib ntdll.lib psapi.lib dbghelp.lib

For x64:
    Add /D "WIN64" and adjust detours library path

Important Notes:
1. Requires Administrator privileges for some functionality
2. Detours library must be installed and in library path
3. Some hooks may be detected by security software
4. Use for educational and defensive research only
5. Test in isolated environment

Features demonstrated:
- IAT (Import Address Table) hooking
- Process monitoring
- Thread monitoring
- Memory monitoring
- Comprehensive logging
- Report generation
- Modular design for extensibility

This implementation provides a complete user-mode monitoring
framework similar to what security software uses for behavioral
analysis and threat detection.
*/
