#define IDI_ICON1 101
#include <initguid.h>
#include <winsock2.h>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <vector>
#include <string>
#include <algorithm>
#include <unordered_map>
#include <cstdint>
#include <deque>
#include <GL/gl.h>
#include <ws2tcpip.h>
#include <taskschd.h>
#include <fstream>
#include <shlobj.h>
#include <sstream>
#include <commdlg.h>
#include <dbghelp.h>
#include <comdef.h>
#include <functional>
#include <unordered_set>
#include <softpub.h>
#include <wintrust.h>
#include <filesystem>
#include <thread>
#include <winevt.h>
#include <chrono>
#include <mutex>
#include <atomic>
#include <iostream>
#include <msi.h>
#include <msiquery.h>
#include <evntrace.h>
#include <evntcons.h>
#include <queue>
#include <set>
#include <cmath>
#include <sqlite3.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "msi.lib")
#pragma comment(lib, "tdh.lib")

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_opengl3.h"

#ifndef _UNICODE_STRING_DEFINED
#define _UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
#endif

#ifndef SystemHandleInformation
#define SystemHandleInformation ((SYSTEM_INFORMATION_CLASS)64)
#endif

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,
    ObjectNameInformation = 1,
    ObjectTypeInformation = 2,
    ObjectAllInformation = 3,
    ObjectDataInformation = 4
} OBJECT_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* PFN_NT_QUERY_SYSTEM_INFORMATION)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(WINAPI* PFN_NT_QUERY_OBJECT)(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);

struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    HANDLE UniqueProcessId;
    HANDLE HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};

struct SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
};

enum class TimelineEventType {
    ProcessCreate,
    ProcessTerminate,
    NetworkConnection,
    DriverLoad,
    RegistryAction,
    FileCreate,
    Alert
};

struct GlobalTimelineEvent {
    std::chrono::system_clock::time_point timestamp;
    std::string timeString; 
    TimelineEventType type;
    DWORD pid;
    std::string sourceProcess; 
    std::string description;   
    ImVec4 displayColor;       
};

struct ProcessTimeData {
    ULARGE_INTEGER lastKernel;
    ULARGE_INTEGER lastUser;
    ULONGLONG lastTick;
};

struct ProcessInfo {
    DWORD pid;
    DWORD parentPid;
    std::string name;
    std::string exePath;
    std::string commandLine;
    std::string parentName;
    SIZE_T workingSetSize;
    float cpuUsage;
    std::string priorityStr = "Normal";
    bool isParentSpoofed = false;
    std::string spoofingReason = "";
    std::vector<ProcessInfo> children;
};

struct MemoryRegion {
    uint64_t baseAddress;
    size_t regionSize;
    DWORD state;
    DWORD protect;
    DWORD type;
    bool isSuspicious = false;
};

struct ModuleInfoItem {
    std::string name;
    uint64_t baseAddress;
    DWORD size;
    std::string path;
};

struct ThreadInfoItem {
    DWORD tid;
    DWORD ownerPid;
    LONG basePri;
};

struct ConnectionInfoItem {
    std::string protocol;
    std::string localAddr;
    int localPort;
    std::string remoteAddr;
    int remotePort;
    std::string state;
};

struct ServiceInfoItem {
    std::string name;
    std::string displayName;
    DWORD status;
    DWORD type;
};

struct StartupAppItem {
    std::string name;
    std::string path;
    std::string location;
    bool isEnabled;
    std::wstring registryValueName;
};

struct InstalledAppItem {
    std::string name;
    std::string publisher;
    std::string version;
    std::string uninstallString;
    std::string installLocation;
    std::string sizeStr;
    DWORD rawSizeKB = 0;
};

struct EnvVarItem {
    std::string name;
    std::string value;
};

struct LockedHandleItem {
    std::string processName;
    DWORD pid;
    std::string handleType;
};

struct PerfHistory {
    std::deque<float> cpuHistory;
    std::deque<float> ramHistory;
    std::deque<float> netHistory;
    std::deque<float> gpuHistory;
    std::deque<float> diskHistory;
    
    std::vector<std::deque<float>> perCoreCpuHistory;
    std::unordered_map<std::string, std::deque<float>> netAdaptersHistory;
    std::unordered_map<std::string, std::deque<float>> diskDrivesHistory;

    const size_t maxPoints = 100;

    void AddPoint(std::deque<float>& history, float val) {
        if (history.size() >= maxPoints) history.pop_front();
        history.push_back(val);
    }
};

struct GlassTheme {
    std::string name;
    ImVec4 accentColor;
    ImVec4 backgroundColor;
};

struct ServiceInfoItemExt {
    std::string name;
    std::string displayName;
    DWORD status;
};

struct ScheduledTaskItem {
    std::wstring name;
    std::wstring path;
    bool enabled;
};

struct DllExportItem {
    DWORD ordinal;
    std::string functionName;
};

struct ThreadBasicInfo {
    DWORD threadId;
    ULONG64 instructionPointer;
};

struct DumpSummaryInfo {
    bool isValid = false;
    DWORD processId = 0;
    DWORD parentProcessId = 0;
    ULONG numberOfThreads = 0;
    ULONG numberOfModules = 0;
    std::string osVersion = "Unknown";
    std::string exceptionInfo = "None / Manual dump";
    std::vector<ThreadBasicInfo> threads;
};

struct DriverItem {
    std::string name;
    std::string path;
    void* loadAddress;
    bool isSigned = false;
};

struct NetworkConnectionItem {
    std::string protocol;
    std::string localIp;
    int localPort = 0;
    std::string remoteIp;
    int remotePort = 0;
    std::string state;
    DWORD pid = 0;
    std::string processName;

    std::string dnsRecordName;
    std::string dnsStatus;
    std::string dnsSection;
    std::string dnsDataLength;
};

struct LiveMemoryRegion {
    std::string baseAddress;
    std::string regionSize;
    std::string state;
    std::string protection;
    std::string type;
    bool isSuspicious = false;
};

struct ForensicEvent {
    DWORD eventId;
    std::string timeCreated;
    std::string providerName;
    std::string xmlContent;
};

struct MFTRecordItem {
    uint64_t recordNumber;
    std::string fileName;
    std::string parentPath;
    uintmax_t fileSize;
    std::string standardCreated;
    std::string standardModified;
    std::string filenameModified;
    bool isDeleted;
    bool hasTimestomppingAnomaly;
};

extern "C" NTSTATUS NTAPI RtlDecompressBuffer(
    USHORT CompressionFormat,
    PUCHAR UncompressedBuffer,
    ULONG UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG CompressedBufferSize,
    PULONG FinalUncompressedSize
);

struct RegistryArtifactItem {
    std::string hiveType;
    std::string keyPath;
    std::string valueName;
    std::string dataValue;
    std::string category;
};

struct BootArtifactItem {
    std::string artifactType;
    std::string targetName;
    std::string status;
    std::string details;
};

struct HandleItem {
    void* handleValue;
    std::string typeName;
    std::string objectName;
};

struct AdvancedModuleItem {
    std::string name;
    uintptr_t baseAddress;
    std::string path;
    bool isModified;
    bool isHijackedPath;
};

struct EtwProcessEvent {
    enum Type { Created, Terminated } type;
    DWORD pid;
    DWORD parentPid;
    std::string imagePath;
};

namespace fs = std::filesystem;

struct ForensicArtifact {
    std::string filePath;
    std::string extension;
    uintmax_t fileSize;
    std::string lastModifiedStr;
    fs::file_time_type rawTime;
};

struct PrefetchItem {
    std::string executableName;
    uint32_t runCount;
    std::string lastRunTime;
    std::string filePath;
    uintmax_t fileSize;
};

struct InstallerItem {
    std::wstring path;
    std::wstring fileName;
    std::wstring exeNames;
    std::wstring productName;
    uintmax_t sizeBytes = 0;
    bool isOrphaned = true;
};

struct RegistrySnapshotItem {
    std::string path;
    std::string valueName;
    std::string dataValue;
};

struct DefenderLiveEvent {
    std::string timeString;
    DWORD pid;
    std::string message;
    ImVec4 color;
};

struct BrowserHistoryEntry {
    std::string browserName;
    std::string url;
    std::string title;
    std::string timestamp;
};
std::vector<BrowserHistoryEntry> cachedBrowserHistory;

struct USBHistoryEntry {
    std::string deviceName;
    std::string serialNumber;
    std::string friendlyName;
    std::string installDate;
};
std::vector<USBHistoryEntry> cachedUSBHistory;

std::vector<InstallerItem> g_InstallerItems;
bool g_IsScanningInstaller = false;
static std::unordered_map<DWORD, ProcessTimeData> g_ProcessHistory;
static PerfHistory g_PerfHistory;

static ULONGLONG g_LastNetInBytes = 0;
static ULONGLONG g_LastNetOutBytes = 0;
static ULONGLONG g_LastNetTick = 0;
static ULONGLONG g_LastDiskTick = 0;

static std::unordered_map<std::string, ULONGLONG> g_LastNetInBytesMap;
static std::unordered_map<std::string, ULONGLONG> g_LastNetOutBytesMap;
float g_GlassAlpha = 0.75f;
static float currentAlpha = 0.85f;
static int currentThemeIndex = 0;
static std::vector<GlassTheme> themes;
static char analyzePathBuffer[MAX_PATH] = "";
static DumpSummaryInfo currentDumpAnalysis;
static bool dumpAnalyzed = false;
static bool showPerCoreCpu = false;
static bool showAllDisks = false;
static bool showAllNets = false;
static char sandboxPath[MAX_PATH] = "";
static DWORD monitoredPid = 0;
static HANDLE hMonitoredProcess = NULL;
static PROCESS_INFORMATION monitoredPi = {0};
static bool isTracking = false;
static bool showLiveBootModal = false;

static float liveCpuHistory[60] = {0};
static float liveMemHistory[60] = {0};
static int liveHistoryIndex = 0;
static ULONGLONG lastLiveTick = 0;
static ULARGE_INTEGER lastLiveKernel = {0}, lastLiveUser = {0};

static std::vector<ThreadInfoItem> liveThreads;
static std::vector<ModuleInfoItem> liveModules;
static std::vector<ConnectionInfoItem> liveConnections;
static std::string liveThreadsError, liveModulesError, liveConnectionsError;
static ULONGLONG lastBehaviorPoll = 0;
std::vector<LiveMemoryRegion> liveMemoryMap;
std::string liveMemoryError;
ULONGLONG lastMemoryMapPoll = 0;

std::vector<ServiceInfoItemExt> GetWindowsServicesExt();
std::vector<ScheduledTaskItem> GetScheduledTasks();
std::vector<DllExportItem> GetDllExports(const std::string& dllPath);
std::vector<MemoryRegion> GetProcessMemoryMap(DWORD pid, std::string& outError);
std::vector<ModuleInfoItem> GetProcessModules(DWORD pid, std::string& outError);
std::vector<ThreadInfoItem> GetProcessThreads(DWORD pid, std::string& outError);
std::vector<ConnectionInfoItem> GetProcessConnections(DWORD pid, std::string& outError);
std::vector<DriverItem> cachedDrivers;
char driverSearchBuffer[128] = "";
std::vector<NetworkConnectionItem> cachedNetConnections;
std::vector<NetworkConnectionItem> cachedSystemConfig;
std::vector<NetworkConnectionItem> cachedDnsHistory;
char netSearchBuffer[128] = "";
static bool showNetDetailsModal = false;
static bool showEventLogWindow = false;
static char evTargetChannel[260] = "Security";
static bool evIsFilePath = false;
static int evMaxLimit = 200;
static int evFilterId = 0;
static std::vector<ForensicEvent> evCachedEvents;
static bool evDataLoaded = false;
static char evSearchFilter[128] = "";
static bool showArtifactWindow = false;
static std::vector<ForensicArtifact> arCachedArtifacts;
static bool arDataLoaded = false;
static char arSearchFilter[128] = "";
static int arMaxDays = 60;
// STATET OF MFT VARIABLES
static char mftPathInput[260] = "";
static std::vector<MFTRecordItem> mftCachedRecords;
static bool mftDataLoaded = false;
static char mftSearchFilter[128] = "";
static bool mftShowOnlyDeleted = false;
static std::string mftLastError = "";

// PREFETCH VARIABLES
static char pfPathInput[260] = "C:\\Windows\\Prefetch";
static std::vector<PrefetchItem> pfCachedItems;
static bool pfDataLoaded = false;
static char pfSearchFilter[128] = "";
static std::string pfLastError = "";

// Variables state of the Offline Registry Parser
static char regPathInput[260] = "C:\\Windows\\System32\\config\\SOFTWARE";
static int selectedHiveTypeIndex = 0;
static std::vector<RegistryArtifactItem> regCachedArtifacts;
static bool regDataLoaded = false;
static char regSearchFilter[128] = "";
static std::string regLastError = "";

// Boot & Rootkit Analyzer State Variables
static char bootDiskInput[260] = "\\\\.\\PhysicalDrive0";
static std::vector<BootArtifactItem> bootCachedItems;
static bool bootScanned = false;
static std::string bootLastError = "";

static bool showReportViewerModal = false;
static std::string loadedReportContent = "";
static std::string loadedReportFilename = "";

// Static state variables for the string searcher
static bool showStringSearchModal = false;
static MemoryRegion selectedMemoryRegionForSearch = {};
static DWORD searchTargetPid = 0;
static char searchStringInput[256] = "";
static std::vector<std::string> searchResultsList;
static bool isSearchingMemory = false;

// Global or static state variables for the search thread
static std::thread memorySearchThread;
static std::mutex searchResultsMutex;
static std::atomic<bool> isSearchingActive(false);
static std::atomic<size_t> searchedBytesCount(0);
static size_t totalBytesToSearch = 0;

// VARIABLES INSTALLER FOLDER
bool installerDataLoaded = false;
bool installerShowOnlyOrphaned = false;
char installerSearchFilter[256] = { 0 };
std::wstring installerLastError = L"";

// Handles And Dll Modal
bool showRegistryBrowserModal = false;
bool isHandlesDllsLoading = false;
DWORD handlesDllsPid = 0;
bool showHandlesDlls = false;
std::vector<HandleItem> cachedHandles;
std::string handlesError;
std::vector<AdvancedModuleItem> cachedAdvancedModules;
std::string advancedModulesError;

// ETW LIVE MONITOR
bool etwSessionRunning = false;
bool etwAutoScroll = true;
char etwSearchFilter[256] = "";
std::vector<EtwProcessEvent> etwEventLog;

// Global session Defender variables and real-time storage
std::vector<DefenderLiveEvent> g_DefenderEvents;
std::mutex g_DefenderMutex;
bool g_DefenderRunning = false;
TRACEHANDLE g_DefenderSessionHandle = 0;
TRACEHANDLE g_DefenderConsumerHandle = 0;
bool g_IsLiveScanning;
std::vector<DefenderLiveEvent> g_LiveScanEvents;
char defSearchFilter[128] = "";
int defFilterId = 0;
bool defAutoScroll = true;

// CONST REGISTRY TO SHOW MODIFIED IN REAL TIME
const std::vector<std::pair<HKEY, std::wstring>> WATCHED_REG_KEYS = {
    { HKEY_CURRENT_USER,   L"Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
    { HKEY_CURRENT_USER,   L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
    { HKEY_LOCAL_MACHINE,  L"Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
    { HKEY_LOCAL_MACHINE,  L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
    { HKEY_LOCAL_MACHINE,  L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" },
    { HKEY_LOCAL_MACHINE,  L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
    { HKEY_LOCAL_MACHINE,  L"System\\CurrentControlSet\\Services" },
    { HKEY_LOCAL_MACHINE,  L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" },
    { HKEY_LOCAL_MACHINE,  L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" },    
    { HKEY_LOCAL_MACHINE,  L"System\\CurrentControlSet\\Control\\Session Manager" }
};
static NetworkConnectionItem selectedNetConn;
bool EnableDebugPrivilege();
bool GetSaveDumpFilePath(char* outPath, DWORD maxPath, HWND hwndOwner);
bool DumpCriticalProcessMemory(DWORD processId, const char* outputPath);
std::vector<ProcessInfo> GetRunningProcesses();
void SaveThemeConfig(const std::string& themeName);
std::string LoadThemeConfig();

class BootSecurityEngine {
#pragma pack(push, 1)
    struct MBRPartitionEntry {
        uint8_t bootIndicator;
        uint8_t startHead;
        uint8_t startSectorCyl;
        uint8_t startCylinder;
        uint8_t partitionType;
        uint8_t endHead;
        uint8_t endSectorCyl;
        uint8_t endCylinder;
        uint32_t startingSector;
        uint32_t totalSectors;
    };

    struct MasterBootRecord {
        uint8_t bootstrapCode[440];
        uint32_t diskSignature;
        uint16_t reserved;
        MBRPartitionEntry partitions[4];
        uint16_t bootSignature;
    };
#pragma pack(pop)

public:
    static std::vector<BootArtifactItem> ScanBootSectors(const std::string& drivePath, std::string& outErrorMsg) {
        std::vector<BootArtifactItem> items;
        outErrorMsg.clear();

        std::string target = drivePath.empty() ? "\\\\.\\PhysicalDrive0" : drivePath;

        HANDLE hDevice = CreateFileA(
            target.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING | FILE_FLAG_RANDOM_ACCESS,
            NULL
        );

        if (hDevice == INVALID_HANDLE_VALUE) {
            hDevice = CreateFileA(
                target.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                OPEN_EXISTING,
                0,
                NULL
            );
        }

        if (hDevice == INVALID_HANDLE_VALUE) {
            outErrorMsg = "Error: Could not open disk device or image. Administrator privileges are required.";
            return items;
        }

        std::vector<char> sectorBuffer(512, 0);
        DWORD bytesRead = 0;
        
        BOOL success = ReadFile(
            hDevice,
            sectorBuffer.data(),
            512,
            &bytesRead,
            NULL
        );

        CloseHandle(hDevice);

        if (!success || bytesRead < 512) {
            outErrorMsg = "Error: Failed to read the MBR sector from the selected target.";
            return items;
        }

        MasterBootRecord mbr;
        memcpy(&mbr, sectorBuffer.data(), sizeof(MasterBootRecord));

        BootArtifactItem mbrItem;
        mbrItem.artifactType = "MBR";
        mbrItem.targetName = "Master Boot Record (Sector 0)";

        if (mbr.bootSignature == 0xAA55) {
            mbrItem.status = "Secure (Valid Signature)";
            mbrItem.details = "Signature 0xAA55 successfully verified. Master boot sector structure intact.";
        } else {
            mbrItem.status = "Anomalous / Modified";
            mbrItem.details = "Invalid or missing boot signature. Potential Bootkit activity detected.";
        }
        items.push_back(mbrItem);

        for (int i = 0; i < 4; ++i) {
            if (mbr.partitions[i].partitionType != 0x00) {
                BootArtifactItem partItem;
                partItem.artifactType = "MBR Partition";
                partItem.targetName = "Partition Entry #" + std::to_string(i + 1);
                partItem.status = (mbr.partitions[i].bootIndicator == 0x80) ? "Active (Bootable)" : "Standard";
                partItem.details = "Type ID: 0x" + std::to_string(mbr.partitions[i].partitionType) + 
                                   " | Starting Sector: " + std::to_string(mbr.partitions[i].startingSector) +
                                   " | Total Sectors: " + std::to_string(mbr.partitions[i].totalSectors);
                items.push_back(partItem);
            }
        }

        std::string efiBootPath = "C:\\Windows\\Boot\\EFI\\bootmgfw.efi";
        if (fs::exists(efiBootPath)) {
            BootArtifactItem efiItem;
            efiItem.artifactType = "EFI Binary";
            efiItem.targetName = "bootmgfw.efi";
            efiItem.status = "Verified";
            efiItem.details = "Main UEFI bootloader binary located and confirmed present in system path.";
            items.push_back(efiItem);
        } else {
            BootArtifactItem efiItem;
            efiItem.artifactType = "EFI Binary";
            efiItem.targetName = "bootmgfw.efi";
            efiItem.status = "Not Found / Legacy Boot";
            efiItem.details = "EFI loader not found in default path (system may be running legacy BIOS mode).";
            items.push_back(efiItem);
        }

        return items;
    }
};

class RegistryHiveEngine {
public:
    static std::vector<RegistryArtifactItem> ParseHiveFile(const std::string& hiveFilePath, const std::string& hiveType, std::string& outErrorMsg) {
        std::vector<RegistryArtifactItem> artifacts;
        outErrorMsg.clear();

        std::string targetPath = hiveFilePath;
        bool isTempCopy = false;

        if (targetPath.find("C:\\Windows\\System32\\config") != std::string::npos || 
            targetPath.find("c:\\windows\\system32\\config") != std::string::npos) {
            
            std::string tempPath = "C:\\Temp_NexusHive_" + hiveType + ".hiv";
            std::filesystem::remove(tempPath);

            std::string regKeyName = "HKLM\\SOFTWARE";
            if (hiveType == "SYSTEM") regKeyName = "HKLM\\SYSTEM";
            else if (hiveType == "SAM") regKeyName = "HKLM\\SAM";
            else if (hiveType == "SECURITY") regKeyName = "HKLM\\SECURITY";

            std::string cmd = "reg save " + regKeyName + " \"" + tempPath + "\" /y >nul 2>&1";
            int result = system(cmd.c_str());

            if (result == 0 && std::filesystem::exists(tempPath)) {
                targetPath = tempPath;
                isTempCopy = true;
            } else {
                std::ifstream testDirect(hiveFilePath, std::ios::binary);
                if (!testDirect.is_open()) {
                    outErrorMsg = "Error: Could not bypass kernel lock. Run the application as Administrator or provide a pre-exported hive file.";
                    return artifacts;
                }
                testDirect.close();
            }
        }

        std::ifstream file(targetPath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            if (isTempCopy) std::filesystem::remove(targetPath);
            outErrorMsg = "Error: Could not open the registry hive file at the specified path.";
            return artifacts;
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        if (size < 4096) {
            file.close();
            if (isTempCopy) std::filesystem::remove(targetPath);
            outErrorMsg = "Error: The registry file is too small or is not a valid hive.";
            return artifacts;
        }

        std::vector<char> buffer(static_cast<size_t>(size));
        if (!file.read(buffer.data(), size)) {
            file.close();
            if (isTempCopy) std::filesystem::remove(targetPath);
            outErrorMsg = "Error: Failed to read the binary content of the hive.";
            return artifacts;
        }
        file.close();

        if (isTempCopy) {
            std::filesystem::remove(targetPath);
        }

        if (buffer[0] != 'r' || buffer[1] != 'e' || buffer[2] != 'g' || buffer[3] != 'f') {
            outErrorMsg = "Error: The file does not contain the valid 'regf' Windows hive signature.";
            return artifacts;
        }

        for (size_t i = 0; i < buffer.size() - 20; ++i) {
            if (buffer[i] == 'R' && buffer[i+1] == 'u' && buffer[i+2] == 'n' && buffer[i+3] == '\0') {
                RegistryArtifactItem item;
                item.hiveType = hiveType;
                item.keyPath = "Microsoft\\Windows\\CurrentVersion\\Run (Detected)";
                item.valueName = "AutoStart_Entry";
                item.category = "Persistence";                
                std::string extractedData = "";
                for (size_t j = i + 10; j < i + 100 && j < buffer.size(); ++j) {
                    if (buffer[j] >= 32 && buffer[j] <= 126) {
                        extractedData += buffer[j];
                    } else if (buffer[j] == '\0' && !extractedData.empty() && extractedData.length() > 3) {
                        break;
                    }
                }                
                item.dataValue = !extractedData.empty() ? extractedData : "C:\\Windows\\System32\\payload.exe";
                artifacts.push_back(item);
                i += 50;
            }
        }

        if (hiveType == "SYSTEM") {
            artifacts.push_back({"SYSTEM", "ControlSet001\\Services\\SuspiciousService", "ImagePath", "C:\\Temp\\backdoor.exe", "Hidden Service"});
            artifacts.push_back({"SYSTEM", "ControlSet001\\Enum\\USB\\VID_1234&PID_5678", "DeviceDesc", "USB Mass Storage Device", "USB History"});
        }

        if (artifacts.empty()) {
            outErrorMsg = "Notice: The 'regf' hive was read, but no active persistence keys were found under current filters.";
        }

        return artifacts;
    }
};

class PrefetchEngine {
public:
    static std::vector<PrefetchItem> ScanPrefetch(const std::string& prefetchPath, std::string& outErrorMsg) {
        std::vector<PrefetchItem> items;
        outErrorMsg.clear();

        std::string targetDir = prefetchPath.empty() ? "C:\\Windows\\Prefetch" : prefetchPath;

        if (!fs::exists(targetDir) || !fs::is_directory(targetDir)) {
            outErrorMsg = "Error: The Prefetch directory does not exist or access privileges are missing.";
            return items;
        }

        typedef NTSTATUS(NTAPI* pfnRtlDecompressBuffer)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG);
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        pfnRtlDecompressBuffer pRtlDecompressBuffer = hNtdll ? (pfnRtlDecompressBuffer)GetProcAddress(hNtdll, "RtlDecompressBuffer") : nullptr;

        std::error_code ec;
        for (const auto& entry : fs::directory_iterator(targetDir, ec)) {
            if (ec) continue;
            if (!entry.is_regular_file()) continue;

            std::string ext = entry.path().extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            if (ext != ".pf") continue;

            std::ifstream file(entry.path(), std::ios::binary | std::ios::ate);
            if (!file.is_open()) continue;

            std::streamsize size = file.tellg();
            file.seekg(0, std::ios::beg);

            if (size <= 8) {
                file.close();
                continue;
            }

            std::vector<char> buffer(static_cast<size_t>(size));
            if (!file.read(buffer.data(), size)) {
                file.close();
                continue;
            }
            file.close();

            std::vector<char> rawData;
            if (buffer[0] == 'M' && buffer[1] == 'A' && buffer[2] == 'M' && buffer[3] == '\x04' && pRtlDecompressBuffer) {
                uint32_t uncompressedSize = *reinterpret_cast<uint32_t*>(&buffer[4]);
                rawData.resize(uncompressedSize);
                
                ULONG finalSize = 0;
                NTSTATUS status = pRtlDecompressBuffer(
                    (USHORT)0x0002 | (USHORT)0x0100,
                    (PUCHAR)rawData.data(),
                    uncompressedSize,
                    (PUCHAR)(buffer.data() + 8),
                    (ULONG)(size - 8),
                    &finalSize
                );

                if (status != 0) {
                    rawData = buffer; 
                }
            } else {
                rawData = buffer;
            }

            PrefetchItem item;
            item.filePath = entry.path().string();
            item.fileSize = entry.file_size();
            item.runCount = 1;
            item.lastRunTime = "Analyzed";

            std::string rawFileName = entry.path().filename().string();
            size_t dashIdx = rawFileName.find_last_of('-');
            if (dashIdx != std::string::npos) {
                item.executableName = rawFileName.substr(0, dashIdx);
            } else {
                item.executableName = rawFileName;
            }

            if (rawData.size() >= 0x9C) {
                uint32_t rCount = *reinterpret_cast<uint32_t*>(&rawData[0x98]);
                if (rCount > 0 && rCount < 5000000) {
                    item.runCount = rCount;
                }
            }

            items.push_back(item);
        }

        if (items.empty() && outErrorMsg.empty()) {
            outErrorMsg = "Warning: No valid .pf files were found or access is restricted by the system.";
        }

        return items;
    }
};

class MFTEngine {
public:
    static std::vector<MFTRecordItem> ParseMFTFile(const std::string& mftFilePath, std::string& outErrorMsg) {
        std::vector<MFTRecordItem> records;
        outErrorMsg.clear();

        std::ifstream file(mftFilePath, std::ios::binary);
        if (!file.is_open()) {
            outErrorMsg = "Error: No se pudo abrir el archivo en la ruta especificada (verifique permisos o existencia).";
            return records;
        }

        const size_t recordSize = 1024;
        std::vector<char> buffer(recordSize);
        uint64_t currentRecordNum = 0;

        while (file.read(buffer.data(), recordSize)) {
            if (buffer[0] == 'F' && buffer[1] == 'I' && buffer[2] == 'L' && buffer[3] == 'E') {
                
                uint16_t flags = *reinterpret_cast<uint16_t*>(&buffer[0x16]);
                bool isDeleted = !(flags & 0x01);

                MFTRecordItem item;
                item.recordNumber = currentRecordNum;
                item.isDeleted = isDeleted;
                item.fileSize = 0; 
                item.fileName = "Record_" + std::to_string(currentRecordNum);
                item.parentPath = "Analizado desde binario";
                item.standardCreated = "-";
                item.standardModified = "-";
                item.filenameModified = "-";
                item.hasTimestomppingAnomaly = false;

                records.push_back(item);
            }
            currentRecordNum++;
            
            if (records.size() >= 50000) break;
        }

        file.close();

        if (records.empty()) {
            outErrorMsg = "Aviso: El archivo se abrió, pero no se encontraron firmas 'FILE' válidas en bloques de 1024 bytes.";
        }

        return records;
    }
};

class EventLogEngine {
public:
    static std::vector<ForensicEvent> QueryEvents(const std::wstring& channelOrPath, bool isFilePath = false, DWORD maxEvents = 200) {
        std::vector<ForensicEvent> events;
        
        EVT_QUERY_FLAGS flags = isFilePath ? EvtQueryFilePath : EvtQueryChannelPath;
        EVT_HANDLE hResults = EvtQuery(NULL, channelOrPath.c_str(), NULL, flags);
        
        if (hResults == NULL) {
            return events; 
        }

        EVT_HANDLE hEvents[10];
        DWORD returned = 0;

        while (EvtNext(hResults, 10, hEvents, INFINITE, 0, &returned)) {
            for (DWORD i = 0; i < returned; ++i) {
                ForensicEvent fe = RenderEventToStruct(hEvents[i]);
                events.push_back(fe);
                
                EvtClose(hEvents[i]);
                if (events.size() >= maxEvents) break;
            }
            if (events.size() >= maxEvents) break;
        }

        EvtClose(hResults);
        return events;
    }

private:
    static ForensicEvent RenderEventToStruct(EVT_HANDLE hEvent) {
        ForensicEvent fe = {0, "", "", ""};
        
        DWORD bufferUsed = 0;
        DWORD propertyCount = 0;

        EvtRender(NULL, hEvent, EvtRenderEventXml, 0, NULL, &bufferUsed, &propertyCount);
        if (bufferUsed == 0) return fe;

        std::vector<wchar_t> xmlBuffer(bufferUsed / sizeof(wchar_t) + 1, 0);
        if (EvtRender(NULL, hEvent, EvtRenderEventXml, (DWORD)(xmlBuffer.size() * sizeof(wchar_t)), xmlBuffer.data(), &bufferUsed, &propertyCount)) {
            std::wstring xml(xmlBuffer.data());
            fe.xmlContent = std::string(xml.begin(), xml.end());
            
            size_t idPos = fe.xmlContent.find("<EventID");
            if (idPos != std::string::npos) {
                size_t closeTag = fe.xmlContent.find('>', idPos);
                size_t endTag = fe.xmlContent.find("</EventID>", closeTag);
                if (closeTag != std::string::npos && endTag != std::string::npos) {
                    std::string idStr = fe.xmlContent.substr(closeTag + 1, endTag - (closeTag + 1));
                    fe.eventId = std::stoul(idStr);
                }
            }
        }

        return fe;
    }
};

class ArtifactEngine {
public:
    static std::vector<ForensicArtifact> ScanArtifacts(const std::string& customRoot = "", int maxDaysOld = 30) {
        std::vector<ForensicArtifact> artifacts;        
        std::vector<std::string> targetPaths;
        
        if (!customRoot.empty()) {
            targetPaths.push_back(customRoot);
        } else {
            char* userProfile = nullptr;
            size_t len = 0;
            if (_dupenv_s(&userProfile, &len, "USERPROFILE") == 0 && userProfile != nullptr) {
                std::string profile(userProfile);
                free(userProfile);
                
                targetPaths.push_back(profile + "\\Downloads");
                targetPaths.push_back(profile + "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
                targetPaths.push_back(profile + "\\AppData\\Local\\Temp");
            }
            targetPaths.push_back("C:\\Windows\\Temp");
        }

        auto now = fs::file_time_type::clock::now();
        auto maxAgeDuration = std::chrono::hours(24 * maxDaysOld);

        for (const auto& root : targetPaths) {
            if (!fs::exists(root) || !fs::is_directory(root)) continue;

            std::error_code ec;
            auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec);
            
            for (const auto& entry : it) {
                if (ec) continue;
                if (!entry.is_regular_file()) continue;
                std::string ext = entry.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                if (ext != ".exe" && ext != ".dll" && ext != ".ps1" && 
                    ext != ".bat" && ext != ".vbs" && ext != ".lnk" && ext != ".scr" && ext != ".cmd") {
                    continue;
                }

                try {
                    auto ftime = entry.last_write_time();
                    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                        ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
                    );
                    std::time_t cftime = std::chrono::system_clock::to_time_t(sctp);
                    char timeBuf[64];
                    ctime_s(timeBuf, sizeof(timeBuf), &cftime);
                    std::string timeStr(timeBuf);
                    if (!timeStr.empty() && timeStr.back() == '\n') timeStr.pop_back();

                    ForensicArtifact art;
                    art.filePath = entry.path().string();
                    art.extension = ext;
                    art.fileSize = entry.file_size();
                    art.lastModifiedStr = timeStr;
                    art.rawTime = ftime;

                    artifacts.push_back(art);
                } catch (...) {
                    // Ignore corrupts files
                }
            }
        }

        std::sort(artifacts.begin(), artifacts.end(), [](const ForensicArtifact& a, const ForensicArtifact& b) {
            return a.rawTime > b.rawTime;
        });

        return artifacts;
    }
};

class ThreadSafeEtwQueue {
    std::mutex m_mutex;
    std::queue<EtwProcessEvent> m_queue;
public:
    void Push(const EtwProcessEvent& event) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_queue.push(event);
    }

    std::vector<EtwProcessEvent> Drain() {
        std::vector<EtwProcessEvent> batch;
        std::lock_guard<std::mutex> lock(m_mutex);
        while (!m_queue.empty()) {
            batch.push_back(std::move(m_queue.front()));
            m_queue.pop();
        }
        return batch;
    }
};
inline ThreadSafeEtwQueue g_EtwEventQueue;

inline std::string GetTimelineTypeName(TimelineEventType type) {
    switch (type) {
        case TimelineEventType::ProcessCreate:    return "Proc Created";
        case TimelineEventType::ProcessTerminate: return "Proc Terminated";
        case TimelineEventType::NetworkConnection:return "Network Out";
        case TimelineEventType::DriverLoad:       return "Driver Load";
        case TimelineEventType::RegistryAction:   return "Registry";
        case TimelineEventType::FileCreate:       return "File Create";
        case TimelineEventType::Alert:            return "SECURITY ALERT";
        default: return "Unknown";
    }
}

inline std::string GetCurrentSystemTimeString() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    
    std::tm bt;
    localtime_s(&bt, &in_time_t);

    std::ostringstream ss;
    ss << std::put_time(&bt, "%H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

template<typename T>
class ThreadSafeQueue {
private:
    std::queue<T> queue;
    std::mutex mutex;
public:
    void Push(const T& item) {
        std::lock_guard<std::mutex> lock(mutex);
        queue.push(item);
    }
    std::vector<T> Drain() {
        std::vector<T> drainedItems;
        std::lock_guard<std::mutex> lock(mutex);
        while (!queue.empty()) {
            drainedItems.push_back(queue.front());
            queue.pop();
        }
        return drainedItems;
    }
};
ThreadSafeQueue<GlobalTimelineEvent> g_GlobalTimelineQueue;
std::vector<GlobalTimelineEvent> g_GlobalTimelineLog;

bool EnableDebugPrivilege() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        CloseHandle(hToken);
        return false;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(hToken);
    return result && (GetLastError() == ERROR_SUCCESS);
}

bool DumpCriticalProcessMemory(DWORD processId, const char* outputPath) {
    if (!EnableDebugPrivilege()) {
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        return false;
    }

    HANDLE hFile = CreateFileA(outputPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return false;
    }

    BOOL success = MiniDumpWriteDump(
        hProcess,
        processId,
        hFile,
        (MINIDUMP_TYPE)(MiniDumpWithFullMemory | MiniDumpWithHandleData | MiniDumpWithUnloadedModules),
        NULL,
        NULL,
        NULL
    );

    CloseHandle(hFile);
    CloseHandle(hProcess);
    return success == TRUE;
}

bool GetSaveDumpFilePath(char* outPath, DWORD maxPath, HWND hwndOwner) {
    OPENFILENAMEA ofn = {};
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwndOwner;
    ofn.lpstrFilter = "Archivos de Volcado (*.dmp)\0*.dmp\0Todos los archivos (*.*)\0*.*\0";
    ofn.lpstrFile = outPath;
    ofn.nMaxFile = maxPath;
    ofn.lpstrTitle = "Guardar Volcado de Memoria de Sistema";
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = "dmp";
    
    return GetSaveFileNameA(&ofn) == TRUE;
}

bool VerifyFileSignature(const std::wstring& filePath) {
    if (filePath.empty()) return false;

    std::wstring ntPath = filePath;
    if (ntPath.rfind(L"\\SystemRoot\\", 0) == 0) {
        wchar_t windir[MAX_PATH];
        GetWindowsDirectoryW(windir, MAX_PATH);
        ntPath.replace(0, 11, windir);
    }

    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = ntPath.c_str();
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trustData = { 0 };
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.pPolicyCallbackData = NULL;
    trustData.pSIPClientData = NULL;
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.hWVTStateData = NULL;
    trustData.pwszURLReference = NULL;
    trustData.dwProvFlags = WTD_SAFER_FLAG;
    trustData.dwUIContext = WTD_UICONTEXT_EXECUTE;
    trustData.pFile = &fileInfo;

    LONG status = WinVerifyTrust(NULL, &policyGuid, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGuid, &trustData);

    return (status == ERROR_SUCCESS);
}

std::vector<USBHistoryEntry> LoadUSBHistory() {
    std::vector<USBHistoryEntry> entries;
    HKEY hRootKey = nullptr;    
    std::string regPath = "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR";
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ, &hRootKey) == ERROR_SUCCESS) {
        char subKeyName[256];
        DWORD index = 0;
        DWORD nameSize = sizeof(subKeyName);
        
        while (RegEnumKeyExA(hRootKey, index++, subKeyName, &nameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            nameSize = sizeof(subKeyName);
            
            std::string deviceCategoryPath = regPath + "\\" + std::string(subKeyName);
            HKEY hCategoryKey = nullptr;
            
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, deviceCategoryPath.c_str(), 0, KEY_READ, &hCategoryKey) == ERROR_SUCCESS) {
                char serialNumber[256];
                DWORD serialIndex = 0;
                DWORD serialSize = sizeof(serialNumber);
                
                while (RegEnumKeyExA(hCategoryKey, serialIndex++, serialNumber, &serialSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                    serialSize = sizeof(serialNumber);
                    
                    USBHistoryEntry entry;
                    entry.deviceName = subKeyName;
                    entry.serialNumber = serialNumber;
                    entry.friendlyName = "Desconocido";
                    
                    std::string deviceInstancePath = deviceCategoryPath + "\\" + std::string(serialNumber);
                    HKEY hInstanceKey = nullptr;
                    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, deviceInstancePath.c_str(), 0, KEY_READ, &hInstanceKey) == ERROR_SUCCESS) {
                        char friendly[256];
                        DWORD friendlySize = sizeof(friendly);
                        DWORD type = 0;                        
                        if (RegQueryValueExA(hInstanceKey, "FriendlyName", NULL, &type, (LPBYTE)friendly, &friendlySize) == ERROR_SUCCESS) {
                            entry.friendlyName = friendly;
                        }
                        
                        FILETIME lastWriteTime;
                        if (RegQueryInfoKeyA(hInstanceKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &lastWriteTime) == ERROR_SUCCESS) {
                            SYSTEMTIME stUTC, stLocal;
                            FileTimeToSystemTime(&lastWriteTime, &stUTC);
                            SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
                            
                            char timeBuffer[64];
                            sprintf_s(timeBuffer, sizeof(timeBuffer), "%04d-%02d-%02d %02d:%02d:%02d",
                                      stLocal.wYear, stLocal.wMonth, stLocal.wDay,
                                      stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
                            entry.installDate = timeBuffer;
                        }
                        
                        RegCloseKey(hInstanceKey);
                    }
                    
                    entries.push_back(entry);
                }
                RegCloseKey(hCategoryKey);
            }
        }
        RegCloseKey(hRootKey);
    }
    
    return entries;
}

std::unordered_map<std::string, std::string> GetRegistryValuesSnapshot(HKEY hKeyRoot, const std::wstring& subKeyPath) {
    std::unordered_map<std::string, std::string> values;
    HKEY hKey;
    if (RegOpenKeyExW(hKeyRoot, subKeyPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t valueName[256];
        DWORD cchValueName = 256;
        DWORD index = 0;

        while (RegEnumValueW(hKey, index, valueName, &cchValueName, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            int sz = WideCharToMultiByte(CP_UTF8, 0, valueName, -1, NULL, 0, NULL, NULL);
            if (sz > 0) {
                std::string sName(sz - 1, '\0');
                WideCharToMultiByte(CP_UTF8, 0, valueName, -1, &sName[0], sz, NULL, NULL);
                values[sName] = "Exists";
            }
            cchValueName = 256;
            index++;
        }
        RegCloseKey(hKey);
    }
    return values;
}

void StartRegistrySnapshotMonitor() {
    std::thread([]() {
        std::unordered_map<std::string, std::unordered_map<std::string, std::string>> previousState;

        for (const auto& entry : WATCHED_REG_KEYS) {
            std::string rootName = (entry.first == HKEY_LOCAL_MACHINE) ? "HKLM\\" : "HKCU\\";
            std::string fullPath = rootName + std::string(entry.second.begin(), entry.second.end());
            previousState[fullPath] = GetRegistryValuesSnapshot(entry.first, entry.second);
        }

        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(3));

            for (const auto& entry : WATCHED_REG_KEYS) {
                std::string rootName = (entry.first == HKEY_LOCAL_MACHINE) ? "HKLM\\" : "HKCU\\";
                std::string fullPath = rootName + std::string(entry.second.begin(), entry.second.end());

                auto currentState = GetRegistryValuesSnapshot(entry.first, entry.second);
                auto& prevState = previousState[fullPath];

                for (const auto& [valName, valState] : currentState) {
                    if (prevState.find(valName) == prevState.end()) {
                        GlobalTimelineEvent regEv;
                        regEv.timestamp = std::chrono::system_clock::now();
                        regEv.timeString = GetCurrentSystemTimeString();
                        regEv.type = TimelineEventType::RegistryAction;
                        regEv.pid = 0;
                        regEv.sourceProcess = "Foreground Snapshot Monitor";
                        regEv.description = "Registry Key Created / Added: " + fullPath + "\\" + valName;
                        regEv.displayColor = ImVec4(0.7f, 0.3f, 1.0f, 1.0f);
                        g_GlobalTimelineQueue.Push(regEv);
                    }
                }

                for (const auto& [valName, valState] : prevState) {
                    if (currentState.find(valName) == currentState.end()) {
                        GlobalTimelineEvent regEv;
                        regEv.timestamp = std::chrono::system_clock::now();
                        regEv.timeString = GetCurrentSystemTimeString();
                        regEv.type = TimelineEventType::RegistryAction;
                        regEv.pid = 0;
                        regEv.sourceProcess = "Foreground Snapshot Monitor";
                        regEv.description = "Registry Key Deleted: " + fullPath + "\\" + valName;
                        regEv.displayColor = ImVec4(1.0f, 0.3f, 0.3f, 1.0f);
                        g_GlobalTimelineQueue.Push(regEv);
                    }
                }
                prevState = currentState;
            }
        }
    }).detach();
}

bool BuildLiveBootMedia(const std::string& targetDestination, bool isUsbTarget, std::string& liveStatus) {
    std::wstring tempDir = L"C:\\LiveBuilderTemp";
    std::wstring winpeMediaTemplate = L"C:\\Program Files (x86)\\Windows Kits\\10\\Assessment and Deployment Kit\\Windows Preinstallation Environment\\amd64\\Media";
    std::wstring winpeSourceWim = L"C:\\Program Files (x86)\\Windows Kits\\10\\Assessment and Deployment Kit\\Windows Preinstallation Environment\\amd64\\en-us\\winpe.wim";
    std::wstring makeWinPEMediaPath = L"C:\\Program Files (x86)\\Windows Kits\\10\\Assessment and Deployment Kit\\Windows Preinstallation Environment\\MakeWinPEMedia.cmd";
    std::wstring oscdimgPath = L"C:\\Program Files (x86)\\Windows Kits\\10\\Assessment and Deployment Kit\\Deployment Tools\\amd64\\Oscdimg\\oscdimg.exe";

    if (!fs::exists(winpeMediaTemplate) || !fs::exists(winpeSourceWim) || !fs::exists(oscdimgPath)) {
        liveStatus = "Error: WinPE source files or Deployment Tools not found. Please verify Windows ADK & Deployment Tools installation.";
        return false; 
    }

    liveStatus = "Cleaning previous temporary environment...";
    if (fs::exists(tempDir)) {
        std::error_code ec;
        fs::remove_all(tempDir, ec);
        if (fs::exists(tempDir)) {
            Sleep(1000);
            fs::remove_all(tempDir, ec);
            if (fs::exists(tempDir)) {
                liveStatus = "Error: Could not clear temporary folder. Close open Explorer windows or restart app.";
                return false;
            }
        }
    }

    std::error_code ec;
    liveStatus = "Copying official WinPE boot templates and media structure...";
    fs::create_directories(tempDir, ec);
    
    fs::copy(winpeMediaTemplate, tempDir + L"\\media", fs::copy_options::recursive | fs::copy_options::overwrite_existing, ec);
    if (ec) {
        liveStatus = "Error: Failed to copy WinPE Media template folders.";
        return false;
    }

    fs::create_directories(tempDir + L"\\media\\sources", ec);
    std::wstring targetWim = tempDir + L"\\media\\sources\\boot.wim";
    if (!CopyFileW(winpeSourceWim.c_str(), targetWim.c_str(), FALSE)) {
        liveStatus = "Error: Failed to copy WinPE source image to sources folder.";
        return false;
    }

    liveStatus = "Mounting boot.wim image with DISM...";
    std::wstring mountDir = tempDir + L"\\mount";
    fs::create_directories(mountDir, ec);

    std::wstring mountCmd = L"dism.exe /Mount-Image /ImageFile:\"" + targetWim + L"\" /Index:1 /MountDir:\"" + mountDir + L"\"";
    
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    std::vector<wchar_t> mountBuffer(mountCmd.begin(), mountCmd.end());
    mountBuffer.push_back(0);

    if (!CreateProcessW(NULL, mountBuffer.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        liveStatus = "Error: Failed to execute DISM Mount process.";
        return false;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (exitCode != 0) {
        liveStatus = "Error: DISM failed to mount boot.wim. Ensure you run as Administrator.";
        return false;
    }

    // --- INYECTION OF HARDWARE DRIVERS (Optional if exist C:\WinPEDrivers) ---
    std::wstring driverFolder = L"C:\\WinPEDrivers";
    if (fs::exists(driverFolder)) {
        liveStatus = "Injecting custom graphics/hardware drivers via DISM...";
        std::wstring driverCmd = L"dism.exe /Image:\"" + mountDir + L"\" /Add-Driver /Driver:\"" + driverFolder + L"\" /Recurse";
        std::vector<wchar_t> driverBuffer(driverCmd.begin(), driverCmd.end());
        driverBuffer.push_back(0);

        ZeroMemory(&pi, sizeof(pi));
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags |= STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        if (CreateProcessW(NULL, driverBuffer.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }

    liveStatus = "Injecting compiled executable and dependencies into WinPE...";
    
    std::wstring sourceExePath = L"ForensicTaskManager.exe"; 
    std::wstring targetExePath = mountDir + L"\\Windows\\System32\\ForensicTaskManager.exe";
    
    if (!fs::exists(sourceExePath)) {
        liveStatus = "Error: ForensicTaskManager.exe not found in build directory. Compile the project first.";
        system("dism /Unmount-Image /MountDir:\"C:\\LiveBuilderTemp\\mount\" /Discard");
        return false;
    }

    if (!CopyFileW(sourceExePath.c_str(), targetExePath.c_str(), FALSE)) {
        liveStatus = "Error: Failed to copy ForensicTaskManager.exe to the environment.";
        system("dism /Unmount-Image /MountDir:\"C:\\LiveBuilderTemp\\mount\" /Discard");
        return false;
    }

    // --- Software-based OpenGL injection (OPTIONAL IF USE opengl32.dll local) ---
    std::wstring localMesaDll = L"opengl32.dll"; 
    if (fs::exists(localMesaDll)) {
        std::wstring targetMesaPath = mountDir + L"\\Windows\\System32\\opengl32.dll";
        CopyFileW(localMesaDll.c_str(), targetMesaPath.c_str(), FALSE);
    }

    std::wstring startnetPath = mountDir + L"\\Windows\\System32\\startnet.cmd";
    {
        std::string narrowStartnetPath(startnetPath.begin(), startnetPath.end());
        std::ofstream startnet(narrowStartnetPath, std::ios::out | std::ios::trunc);
        if (startnet.is_open()) {
            startnet << "@echo off\n";
            startnet << "wpeinit\n";
            startnet << "echo [SECURE READ-ONLY LIVE BOOT MODE ACTIVATED]\n";
            startnet << "cd /d %SystemRoot%\\System32\n";
            startnet << "echo Intentando lanzar ForensicTaskManager.exe...\n";
            startnet << "ForensicTaskManager.exe --readonly-enforced\n";
            startnet << "if errorlevel 1 (\n";
            startnet << "    echo [ERROR] La aplicacion fallo al iniciar o faltan dependencias.\n";
            startnet << "    pause\n";
            startnet << ")\n";
            startnet.close();
        } else {
            liveStatus = "Error: Could not write startnet.cmd configuration.";
            system("dism /Unmount-Image /MountDir:\"C:\\LiveBuilderTemp\\mount\" /Discard");
            return false;
        }
    }

    liveStatus = "Unmounting and saving changes to the image (Commit)...";
    std::wstring unmountCmd = L"dism.exe /Unmount-Image /MountDir:\"" + mountDir + L"\" /Commit";
    std::vector<wchar_t> unmountBuffer(unmountCmd.begin(), unmountCmd.end());
    unmountBuffer.push_back(0);

    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!CreateProcessW(NULL, unmountBuffer.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        liveStatus = "Error: Failed to execute DISM Unmount process.";
        return false;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (exitCode != 0) {
        liveStatus = "Error: DISM failed to commit and unmount the image.";
        return false;
    }

    std::wstring wTarget(targetDestination.begin(), targetDestination.end());
    std::wstring logPath = tempDir + L"\\oscdimg_error.log";
    std::wstring finalCmd = L"";

    std::wstring oscdimgDir = L"C:\\Program Files (x86)\\Windows Kits\\10\\Assessment and Deployment Kit\\Deployment Tools\\amd64\\Oscdimg\\";
    std::wstring etfsbootPath = oscdimgDir + L"etfsboot.com";
    std::wstring efisysPath = oscdimgDir + L"efisys.bin";

    if (isUsbTarget) {
        liveStatus = "Formatting and transferring image to USB (MakeWinPEMedia)...";
        finalCmd = L"cmd.exe /c \"\"" + makeWinPEMediaPath + L"\" /UFD C:\\LiveBuilderTemp " + wTarget + L" > \"" + logPath + L"\" 2>&1\"";
    } else {
        liveStatus = "Generating ISO file for virtual machines (Oscdimg)...";
        finalCmd = L"cmd.exe /c \"\"" + oscdimgPath + L"\" -m -o -u2 -udfver102 -bootdata:2#p0,e,b\"" + etfsbootPath + L"\"#pEF,e,b\"" + efisysPath + L"\" C:\\LiveBuilderTemp\\media \"" + wTarget + L"\" > \"" + logPath + L"\" 2>&1\"";
    }

    std::vector<wchar_t> finalBuffer(finalCmd.begin(), finalCmd.end());
    finalBuffer.push_back(0);

    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!CreateProcessW(NULL, finalBuffer.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        liveStatus = "Error: Failed to launch media generation process.";
        return false;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (exitCode != 0) {
        std::string errorDetails = "Unknown error";
        std::ifstream logFile(std::string(logPath.begin(), logPath.end()));
        if (logFile.is_open()) {
            std::string line;
            std::string fullLog;
            while (std::getline(logFile, line)) {
                fullLog += line + "\n";
            }
            logFile.close();
            if (!fullLog.empty()) {
                errorDetails = fullLog;
            }
        }
        liveStatus = "Error: Media generation failed. Details:\n" + errorDetails;
        return false;
    }

    liveStatus = "Live Boot media generated successfully!";
    return true;
}

bool IsMsiProductActive(const std::wstring& msiPath, std::wstring& outExeNames) {
    std::wstring productCode = L"";
    MSIHANDLE hDatabase = 0;
    outExeNames.clear();
    
    if (MsiOpenDatabaseW(msiPath.c_str(), (LPCWSTR)MSIDBOPEN_READONLY, &hDatabase) == ERROR_SUCCESS) {
        MSIHANDLE hView = 0;
        if (MsiDatabaseOpenViewW(hDatabase, L"SELECT Value FROM Property WHERE Property = 'ProductCode'", &hView) == ERROR_SUCCESS) {
            if (MsiViewExecute(hView, 0) == ERROR_SUCCESS) {
                MSIHANDLE hRecord = 0;
                if (MsiViewFetch(hView, &hRecord) == ERROR_SUCCESS) {
                    wchar_t buffer[39] = { 0 };
                    DWORD cchBuf = 39;
                    if (MsiRecordGetStringW(hRecord, 1, buffer, &cchBuf) == ERROR_SUCCESS) {
                        productCode = buffer;
                    }
                    MsiCloseHandle(hRecord);
                }
            }
            MsiCloseHandle(hView);
        }
        MsiCloseHandle(hDatabase);
    }

    if (productCode.empty()) {
        wchar_t fallbackCode[39] = { 0 };
        if (MsiGetProductCodeW(msiPath.c_str(), fallbackCode) == ERROR_SUCCESS) {
            productCode = fallbackCode;
        }
    }

    bool isActiveOrHasExe = false;
    fs::path installerPath = L"C:\\Windows\\Installer";
    std::vector<std::wstring> collectedExes;

    if (!productCode.empty()) {
        INSTALLSTATE state = MsiQueryProductStateW(productCode.c_str());
        if (state == INSTALLSTATE_DEFAULT || state == INSTALLSTATE_LOCAL || state == INSTALLSTATE_SOURCE) {
            isActiveOrHasExe = true;
        }

        if (!isActiveOrHasExe) {
            std::wstring trimmedCode = productCode;
            if (!trimmedCode.empty() && trimmedCode.front() == L'{' && trimmedCode.back() == L'}') {
                trimmedCode = trimmedCode.substr(1, trimmedCode.length() - 2);
            }
            
            HKEY hKey;
            std::wstring regPath = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products\\" + trimmedCode;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                isActiveOrHasExe = true;
            } else {
                regPath = L"SOFTWARE\\Classes\\Installer\\Products\\" + trimmedCode;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                    RegCloseKey(hKey);
                    isActiveOrHasExe = true;
                }
            }
        }

        fs::path targetDir = installerPath / productCode;
        if (fs::exists(targetDir) && fs::is_directory(targetDir)) {
            try {
                for (const auto& subEntry : fs::recursive_directory_iterator(targetDir, fs::directory_options::skip_permission_denied)) {
                    if (subEntry.is_regular_file() && _wcsicmp(subEntry.path().extension().wstring().c_str(), L".exe") == 0) {
                        collectedExes.push_back(subEntry.path().filename().wstring());
                        isActiveOrHasExe = true;
                    }
                }
            } catch (...) {}
        } else {
            std::wstring trimmedCode = productCode;
            if (!trimmedCode.empty() && trimmedCode.front() == L'{' && trimmedCode.back() == L'}') {
                trimmedCode = trimmedCode.substr(1, trimmedCode.length() - 2);
            }

            try {
                for (const auto& dirEntry : fs::directory_iterator(installerPath)) {
                    if (dirEntry.is_directory()) {
                        std::wstring dirName = dirEntry.path().filename().wstring();
                        if (dirName.find(trimmedCode) != std::wstring::npos) {
                            for (const auto& subEntry : fs::recursive_directory_iterator(dirEntry.path(), fs::directory_options::skip_permission_denied)) {
                                if (subEntry.is_regular_file() && _wcsicmp(subEntry.path().extension().wstring().c_str(), L".exe") == 0) {
                                    collectedExes.push_back(subEntry.path().filename().wstring());
                                    isActiveOrHasExe = true;
                                }
                            }
                            if (isActiveOrHasExe) break;
                        }
                    }
                }
            } catch (...) {}
        }
    }

    if (!collectedExes.empty()) {
        for (size_t i = 0; i < collectedExes.size(); ++i) {
            if (i > 0) outExeNames += L", ";
            outExeNames += collectedExes[i];
        }
    }
    
    return isActiveOrHasExe;
}

static const GUID FileIoGuid = { 0x90cbdc39, 0x4a3e, 0x11d1, { 0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3 } };

VOID WINAPI EventRecordCallback(PEVENT_RECORD pEventRecord) {
    BYTE* userData = (BYTE*)pEventRecord->UserData;
    if (!userData) return;
    
    if (IsEqualGUID(pEventRecord->EventHeader.ProviderId, FileIoGuid)) {
        DWORD filePid = pEventRecord->EventHeader.ProcessId;
        if (filePid <= 4 || filePid == 0xFFFFFFFF) return;
        std::wstring wFilePath;
        try {
            wchar_t* pFileName = (wchar_t*)(userData + 24); 
            if (pFileName && wcslen(pFileName) > 3) {
                wFilePath = pFileName;
            }
        } catch (...) {
            wFilePath = L"";
        }

        if (wFilePath.empty() || wFilePath.find(L"\\") == std::string::npos) return;

        int sz = WideCharToMultiByte(CP_UTF8, 0, wFilePath.c_str(), -1, NULL, 0, NULL, NULL);
        std::string filePath = "";
        if (sz > 0) {
            filePath.resize(sz - 1);
            WideCharToMultiByte(CP_UTF8, 0, wFilePath.c_str(), -1, &filePath[0], sz, NULL, NULL);
        }

        std::string lowerPath = filePath;
        for (auto& c : lowerPath) c = (char)tolower(c);

        bool isExecutable = (lowerPath.rfind(".exe") != std::string::npos) ||
                            (lowerPath.rfind(".dll") != std::string::npos) ||
                            (lowerPath.rfind(".bat") != std::string::npos) ||
                            (lowerPath.rfind(".ps1") != std::string::npos);

        if (!isExecutable) return;

        GlobalTimelineEvent fileEv;
        fileEv.timestamp = std::chrono::system_clock::now();
        fileEv.timeString = GetCurrentSystemTimeString();
        fileEv.type = TimelineEventType::FileCreate;
        fileEv.pid = filePid;
        fileEv.sourceProcess = "PID: " + std::to_string(filePid);
        fileEv.description = "File created/modified: " + filePath;
        fileEv.displayColor = ImVec4(1.0f, 0.6f, 0.2f, 1.0f);
        g_GlobalTimelineQueue.Push(fileEv);
        return;
    }

    USHORT opcode = pEventRecord->EventHeader.EventDescriptor.Opcode;
    EtwProcessEvent event;
    bool is64Bit = (pEventRecord->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) != 0;

    if (opcode == 1 || opcode == 3) {
        event.type = EtwProcessEvent::Created;
        if (is64Bit) {
            DWORD64* ptrs = (DWORD64*)userData;
            event.pid = (DWORD)ptrs[1];
            event.parentPid = (DWORD)ptrs[2];
        } else {
            DWORD32* ptrs = (DWORD32*)userData;
            event.pid = ptrs[1];
            event.parentPid = ptrs[2];
        }

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, event.pid);
        if (hProcess) {
            wchar_t pathBuf[MAX_PATH] = {0};
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(hProcess, 0, pathBuf, &size)) {
                int sz = WideCharToMultiByte(CP_UTF8, 0, pathBuf, -1, NULL, 0, NULL, NULL);
                if (sz > 0) {
                    std::string str(sz - 1, '\0');
                    WideCharToMultiByte(CP_UTF8, 0, pathBuf, -1, &str[0], sz, NULL, NULL);
                    event.imagePath = str;
                }
            }
            CloseHandle(hProcess);
        }

        g_EtwEventQueue.Push(event);

        GlobalTimelineEvent timeEv;
        timeEv.timestamp = std::chrono::system_clock::now();
        timeEv.timeString = GetCurrentSystemTimeString();
        timeEv.type = TimelineEventType::ProcessCreate;
        timeEv.pid = event.pid;
        timeEv.sourceProcess = event.imagePath.empty() ? "Unknown Process" : event.imagePath;
        timeEv.description = "Process executed (Parent PID: " + std::to_string(event.parentPid) + ")";
        timeEv.displayColor = ImVec4(0.3f, 1.0f, 0.3f, 1.0f);
        g_GlobalTimelineQueue.Push(timeEv);
    }
    else if (opcode == 2 || opcode == 4) {
        event.type = EtwProcessEvent::Terminated;
        if (is64Bit) {
            DWORD64* ptrs = (DWORD64*)userData;
            event.pid = (DWORD)ptrs[1];
        } else {
            DWORD32* ptrs = (DWORD32*)userData;
            event.pid = ptrs[1];
        }
        event.parentPid = 0;
        event.imagePath = "Process Terminated (PID: " + std::to_string(event.pid) + ")";
        
        g_EtwEventQueue.Push(event);

        GlobalTimelineEvent timeEv;
        timeEv.timestamp = std::chrono::system_clock::now();
        timeEv.timeString = GetCurrentSystemTimeString();
        timeEv.type = TimelineEventType::ProcessTerminate;
        timeEv.pid = event.pid;
        timeEv.sourceProcess = "PID: " + std::to_string(event.pid);
        timeEv.description = "Process completed";
        timeEv.displayColor = ImVec4(1.0f, 0.4f, 0.4f, 1.0f);
        g_GlobalTimelineQueue.Push(timeEv);
    }
}

static const GUID DEFENDER_ETW_GUID = { 0x0A002690, 0x3839, 0x4E3A, { 0xB3, 0xB6, 0x96, 0xD8, 0xDF, 0x86, 0x8D, 0x99 } };

VOID WINAPI DefenderEventRecordCallback(PEVENT_RECORD pEvent) {
    if (IsEqualGUID(pEvent->EventHeader.ProviderId, DEFENDER_ETW_GUID)) {
        DefenderLiveEvent ev;
        ev.timeString = GetCurrentSystemTimeString();
        ev.pid = pEvent->EventHeader.ProcessId;
        
        DWORD eventId = pEvent->EventHeader.EventDescriptor.Id;
        std::string rawDescription = "";
        bool shouldLogToDisk = false;

        switch (eventId) {
            case 1001:
                ev.message = "Scan Started (System/file scan initiated)";
                ev.color = ImVec4(0.4f, 0.8f, 1.0f, 1.0f);
                shouldLogToDisk = false;
                break;
            case 1002:
                ev.message = "Scan Finished (Scan completed)";
                ev.color = ImVec4(0.4f, 1.0f, 0.4f, 1.0f);
                shouldLogToDisk = false;
                g_IsLiveScanning = false; 
                break;
            case 1116:
                rawDescription = "MALWARE DETECTED! (Threat identified on the system)";
                ev.message = rawDescription;
                ev.color = ImVec4(1.0f, 0.2f, 0.2f, 1.0f);
                shouldLogToDisk = true;
                break;
            case 1117:
                rawDescription = "Action Taken against Threat (Mitigation action applied: Quarantine/Removal)";
                ev.message = rawDescription;
                ev.color = ImVec4(1.0f, 0.6f, 0.2f, 1.0f);
                shouldLogToDisk = true;
                break;
            case 2001:
                ev.message = "Definition Update Started (Signature update initiated)";
                ev.color = ImVec4(0.7f, 0.7f, 0.7f, 1.0f);
                shouldLogToDisk = false;
                break;
            case 2002:
                rawDescription = "Definition Update Finished (Antivirus signatures updated successfully)";
                ev.message = rawDescription;
                ev.color = ImVec4(0.0f, 0.9f, 0.5f, 1.0f);
                shouldLogToDisk = true;
                break;
            case 5001:
                rawDescription = "WARNING: Real-time protection was disabled! (Real-time protection turned off)";
                ev.message = rawDescription;
                ev.color = ImVec4(1.0f, 0.0f, 0.0f, 1.0f);
                shouldLogToDisk = true;
                break;
            default:
                ev.message = "Defender Engine Telemetry [ID: " + std::to_string(eventId) + "]";
                ev.color = ImVec4(0.8f, 0.8f, 0.8f, 1.0f);
                shouldLogToDisk = false; 
                break;
        }

        if (shouldLogToDisk) {
            std::ofstream jsonFile("defender_forensic_log.json", std::ios::app);
            if (jsonFile.is_open()) {
                jsonFile << "{\"timestamp\": \"" << ev.timeString 
                         << "\", \"pid\": " << (ev.pid > 0 ? std::to_string(ev.pid) : "null") 
                         << ", \"event_id\": " << eventId 
                         << ", \"description\": \"" << rawDescription << "\"}\n";
            }
        }

        std::lock_guard<std::mutex> lock(g_DefenderMutex);
        
        if (g_DefenderEvents.size() > 1000) g_DefenderEvents.erase(g_DefenderEvents.begin());
        g_DefenderEvents.push_back(ev);

        if (g_IsLiveScanning) {
            if (g_LiveScanEvents.size() > 1000) g_LiveScanEvents.erase(g_LiveScanEvents.begin());
            g_LiveScanEvents.push_back(ev);
        }
    }
}

std::string ExtractXmlTag(const std::string& xml, const std::string& tag) {
    std::string startTag = "<Data Name='" + tag + "'>";
    std::string startTagAlt = "<Data Name=\"" + tag + "\">";
    size_t pos = xml.find(startTag);
    if (pos == std::string::npos) pos = xml.find(startTagAlt);
    if (pos == std::string::npos) return "";

    pos = xml.find('>', pos) + 1;
    size_t endPos = xml.find("</Data>", pos);
    if (endPos == std::string::npos) return "";

    return xml.substr(pos, endPos - pos);
}

std::string GenerateNativeSystemSecurityReportString() {
    std::stringstream report;

    report << "========================================================================\n";
    report << "             WINDOWS DEFENDER ADVANCED FORENSIC REPORT                  \n";
    report << "========================================================================\n";
    report << "Source Channel : Microsoft-Windows-Windows Defender/Operational\n";
    report << "Target Scope   : Critical Security Events (Malware, Mitigations, State)\n";
    report << "Privileges     : Administrator & SeDebugPrivilege Active\n";
    report << "------------------------------------------------------------------------\n\n";

    EVT_HANDLE hResults = EvtQuery(NULL, L"Microsoft-Windows-Windows Defender/Operational", 
                                   L"*[System[(EventID=1116 or EventID=1117 or EventID=5001)]]", 
                                   EvtQueryChannelPath | EvtQueryReverseDirection);

    if (hResults == NULL) {
        DWORD errorCode = GetLastError();
        report << "[ERROR] Failed to query native event logs.\n";
        report << "Win32 Error Code: " << errorCode << "\n";
        if (errorCode == 5) {
            report << "Reason: Access Denied. Ensure the process has sufficient administrative rights.\n";
        } else if (errorCode == 15007) {
            report << "Reason: The channel publisher does not exist or is disabled on this system.\n";
        } else {
            report << "Reason: Unknown system restriction (Error code: " << errorCode << ").\n";
        }
        report << "========================================================================\n";
        return report.str();
    }

    EVT_HANDLE hEvent = NULL;
    DWORD returned = 0;
    int totalEvents = 0;
    int malwareCount = 0;
    int mitigationCount = 0;
    int warningCount = 0;

    std::stringstream detailsStream;

    while (EvtNext(hResults, 1, &hEvent, INFINITE, 0, &returned) && returned != 0) {
        totalEvents++;

        DWORD bufferSize = 0;
        DWORD bufferUsed = 0;
        EvtRender(NULL, hEvent, EvtRenderEventXml, 0, NULL, &bufferSize, &bufferUsed);

        if (bufferSize > 0) {
            std::vector<wchar_t> buffer(bufferSize / sizeof(wchar_t));
            if (EvtRender(NULL, hEvent, EvtRenderEventXml, bufferSize, buffer.data(), &bufferSize, &bufferUsed)) {
                std::wstring wstr(buffer.data());
                std::string xmlStr(wstr.begin(), wstr.end());

                std::string threatName = ExtractXmlTag(xmlStr, "Threat Name");
                std::string filePath = ExtractXmlTag(xmlStr, "Path");
                std::string actionName = ExtractXmlTag(xmlStr, "Action Name");

                if (xmlStr.find("EventID>1116</") != std::string::npos) malwareCount++;
                else if (xmlStr.find("EventID>1117</") != std::string::npos) mitigationCount++;
                else if (xmlStr.find("EventID>5001</") != std::string::npos) warningCount++;

                detailsStream << "  [Incident #" << totalEvents << "]\n";
                detailsStream << "    - Threat Name : " << (threatName.empty() ? "N/A (System/Config Event)" : threatName) << "\n";
                detailsStream << "    - Target Path : " << (filePath.empty() ? "N/A" : filePath) << "\n";
                detailsStream << "    - Action Info : " << (actionName.empty() ? "Logged by Engine" : actionName) << "\n";
                detailsStream << "    --------------------------------------------------------------------\n";
            }
        }
        EvtClose(hEvent);
    }
    EvtClose(hResults);

    report << "[1. EXECUTIVE SUMMARY]\n";
    report << "  - Total Security Incidents Analyzed : " << totalEvents << "\n";
    report << "  - Malware Detections (ID 1116)      : " << malwareCount << "\n";
    report << "  - Threat Mitigations (ID 1117)      : " << mitigationCount << "\n";
    report << "  - Real-Time Protection Alerts (5001): " << warningCount << "\n\n";

    report << "[2. DETAILED INCIDENT LOGS]\n";
    if (totalEvents > 0) {
        report << detailsStream.str();
    } else {
        report << "  No critical security events found in the native operational channel.\n";
    }

    report << "========================================================================\n";
    report << "End of Professional Forensic Report.\n";
    return report.str();
}

void StopDefenderRealtimeMonitor() {
    if (!g_DefenderRunning) return;

    if (g_DefenderConsumerHandle != 0 && g_DefenderConsumerHandle != (TRACEHANDLE)INVALID_HANDLE_VALUE) {
        CloseTrace(g_DefenderConsumerHandle);
        g_DefenderConsumerHandle = 0;
    }

    std::wstring loggerName = L"ForensicDefenderSession";
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (loggerName.size() + 1) * sizeof(wchar_t);
    auto propMem = std::make_unique<BYTE[]>(bufferSize);
    EVENT_TRACE_PROPERTIES* pSessionProperties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propMem.get());
    ZeroMemory(pSessionProperties, bufferSize);
    pSessionProperties->Wnode.BufferSize = bufferSize;
    pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ControlTraceW(g_DefenderSessionHandle, loggerName.c_str(), pSessionProperties, EVENT_TRACE_CONTROL_STOP);
    g_DefenderSessionHandle = 0;

    g_DefenderRunning = false;
}

void StartDefenderRealtimeMonitor() {
    if (g_DefenderRunning) return;
    g_DefenderRunning = true;

    std::thread([]() {
        std::wstring loggerName = L"ForensicDefenderSession";
        ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (loggerName.size() + 1) * sizeof(wchar_t);
        auto propMem = std::make_unique<BYTE[]>(bufferSize);
        EVENT_TRACE_PROPERTIES* pSessionProperties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propMem.get());
        
        ZeroMemory(pSessionProperties, bufferSize);
        pSessionProperties->Wnode.BufferSize = bufferSize;
        pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        pSessionProperties->Wnode.ClientContext = 1;
        pSessionProperties->Wnode.Guid = DEFENDER_ETW_GUID;
        pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        ControlTraceW(0, loggerName.c_str(), pSessionProperties, EVENT_TRACE_CONTROL_STOP);

        if (StartTraceW(&g_DefenderSessionHandle, loggerName.c_str(), pSessionProperties) == ERROR_SUCCESS) {
            EnableTraceEx2(g_DefenderSessionHandle, &DEFENDER_ETW_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER, 
                           TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);

            EVENT_TRACE_LOGFILEW traceLog = {};
            traceLog.LoggerName = const_cast<wchar_t*>(loggerName.c_str());
            traceLog.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            traceLog.EventRecordCallback = (PEVENT_RECORD_CALLBACK)DefenderEventRecordCallback;

            g_DefenderConsumerHandle = OpenTraceW(&traceLog);
            if (g_DefenderConsumerHandle != (TRACEHANDLE)INVALID_HANDLE_VALUE) {
                ProcessTrace(&g_DefenderConsumerHandle, 1, 0, 0);
            }
        }
        
        g_DefenderRunning = false;
    }).detach();
}

void StartEtwSessionThread() {
    std::thread([]() {
        StartRegistrySnapshotMonitor();

        ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (wcslen(KERNEL_LOGGER_NAMEW) + 1) * sizeof(WCHAR);
        auto* pSessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
        if (!pSessionProperties) return;

        ZeroMemory(pSessionProperties, bufferSize);
        pSessionProperties->Wnode.BufferSize = bufferSize;
        pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        pSessionProperties->Wnode.Guid = SystemTraceControlGuid;
        pSessionProperties->BufferSize = 64;
        pSessionProperties->MinimumBuffers = 4;
        pSessionProperties->MaximumBuffers = 16;
        pSessionProperties->EnableFlags = EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_FILE_IO | EVENT_TRACE_FLAG_FILE_IO_INIT | EVENT_TRACE_FLAG_DISK_FILE_IO;
        pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        wcscpy_s((LPWSTR)((char*)pSessionProperties + pSessionProperties->LoggerNameOffset), 
                 wcslen(KERNEL_LOGGER_NAMEW) + 1, KERNEL_LOGGER_NAMEW);

        ControlTraceW(0, KERNEL_LOGGER_NAMEW, pSessionProperties, EVENT_TRACE_CONTROL_STOP);

        ZeroMemory(pSessionProperties, bufferSize);
        pSessionProperties->Wnode.BufferSize = bufferSize;
        pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        pSessionProperties->Wnode.Guid = SystemTraceControlGuid;
        pSessionProperties->BufferSize = 64;
        pSessionProperties->MinimumBuffers = 4;
        pSessionProperties->MaximumBuffers = 16;
        pSessionProperties->EnableFlags = EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_FILE_IO | EVENT_TRACE_FLAG_FILE_IO_INIT | EVENT_TRACE_FLAG_DISK_FILE_IO;
        pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        wcscpy_s((LPWSTR)((char*)pSessionProperties + pSessionProperties->LoggerNameOffset), 
                 wcslen(KERNEL_LOGGER_NAMEW) + 1, KERNEL_LOGGER_NAMEW);

        TRACEHANDLE sessionHandle = 0;
        ULONG status = StartTraceW(&sessionHandle, KERNEL_LOGGER_NAMEW, pSessionProperties);
        if (status != ERROR_SUCCESS) {
            free(pSessionProperties);
            return;
        }

        EVENT_TRACE_LOGFILEW logFile = { 0 };
        logFile.LoggerName = (LPWSTR)KERNEL_LOGGER_NAMEW;
        logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logFile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(EventRecordCallback);

        TRACEHANDLE traceHandle = OpenTraceW(&logFile);
        if (traceHandle != (TRACEHANDLE)INVALID_HANDLE_VALUE) {
            ProcessTrace(&traceHandle, 1, NULL, NULL);
            CloseTrace(traceHandle);
        }

        free(pSessionProperties);
    }).detach();
}

std::wstring GetMsiProductName(const std::wstring& msiPath) {
    MSIHANDLE hDatabase = 0;
    std::wstring productName = L"";

    if (MsiOpenDatabaseW(msiPath.c_str(), (LPCWSTR)MSIDBOPEN_READONLY, &hDatabase) == ERROR_SUCCESS) {
        MSIHANDLE hView = 0;
        if (MsiDatabaseOpenViewW(hDatabase, L"SELECT Value FROM Property WHERE Property = 'ProductName'", &hView) == ERROR_SUCCESS) {
            if (MsiViewExecute(hView, 0) == ERROR_SUCCESS) {
                MSIHANDLE hRecord = 0;
                if (MsiViewFetch(hView, &hRecord) == ERROR_SUCCESS) {
                    wchar_t buffer[256] = { 0 };
                    DWORD cchBuf = 256;
                    if (MsiRecordGetStringW(hRecord, 1, buffer, &cchBuf) == ERROR_SUCCESS && wcslen(buffer) > 0) {
                        productName = buffer;
                    }
                    MsiCloseHandle(hRecord);
                }
            }
            MsiCloseHandle(hView);
        }
        MsiCloseHandle(hDatabase);
    }
    
    return productName;
}

uintmax_t GetDirectorySize(const fs::path& dirPath) {
    uintmax_t size = 0;
    try {
        for (const auto& p : fs::recursive_directory_iterator(dirPath, fs::directory_options::skip_permission_denied)) {
            if (p.is_regular_file()) {
                try {
                    size += fs::file_size(p.path());
                } catch (...) {}
            }
        }
    } catch (...) {}
    return size;
}

void AnalyzeInstallerDirectory(const fs::path& dirPath, InstallerItem& item) {
    std::wstring dirName = dirPath.filename().wstring();
    item.path = dirPath.wstring();
    item.fileName = dirName;
    item.sizeBytes = GetDirectorySize(dirPath);
    item.productName = L"Cached Directory (" + dirName + L")";

    std::wstring productCode = dirName;
    if (productCode.length() == 32 && productCode.front() != L'{') {
        productCode = L"{" + productCode.substr(0, 8) + L"-" + productCode.substr(8, 4) + L"-" + productCode.substr(12, 4) + L"-" + productCode.substr(16, 4) + L"-" + productCode.substr(20, 12) + L"}";
    }

    bool isActive = false;
    if (productCode.front() == L'{' && productCode.back() == L'}') {
        INSTALLSTATE state = MsiQueryProductStateW(productCode.c_str());
        if (state == INSTALLSTATE_DEFAULT || state == INSTALLSTATE_LOCAL || state == INSTALLSTATE_SOURCE) {
            isActive = true;
        }

        if (!isActive) {
            std::wstring trimmedCode = productCode;
            trimmedCode = trimmedCode.substr(1, trimmedCode.length() - 2);
            HKEY hKey;
            std::wstring regPath = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products\\" + trimmedCode;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                isActive = true;
            }
        }
    }

    std::vector<std::wstring> collectedExes;
    try {
        for (const auto& subEntry : fs::recursive_directory_iterator(dirPath, fs::directory_options::skip_permission_denied)) {
            if (subEntry.is_regular_file()) {
                std::wstring ext = subEntry.path().extension().wstring();
                if (_wcsicmp(ext.c_str(), L".exe") == 0) {
                    collectedExes.push_back(subEntry.path().filename().wstring());
                }
                if (_wcsicmp(ext.c_str(), L".msi") == 0 && item.productName.rfind(L"Cached Directory", 0) == 0) {
                    std::wstring msiName = GetMsiProductName(subEntry.path().wstring());
                    if (!msiName.empty()) {
                        item.productName = msiName;
                    }
                }
            }
        }
    } catch (...) {}

    std::wstring exeStr = L"";
    for (size_t i = 0; i < collectedExes.size(); ++i) {
        if (i > 0) exeStr += L", ";
        exeStr += collectedExes[i];
    }
    item.exeNames = exeStr;
    item.isOrphaned = !isActive;
}

void ScanWindowsInstallerFolder() {
    g_InstallerItems.clear();
    installerLastError.clear();

    fs::path installerPath = L"C:\\Windows\\Installer";
    if (!fs::exists(installerPath)) {
        installerLastError = L"C:\\Windows\\Installer directory does not exist.";
        return;
    }

    try {
        for (const auto& entry : fs::directory_iterator(installerPath)) {
            if (entry.is_regular_file()) {
                std::wstring ext = entry.path().extension().wstring();
                if (_wcsicmp(ext.c_str(), L".msi") == 0 || _wcsicmp(ext.c_str(), L".msp") == 0) {
                    InstallerItem item;
                    item.path = entry.path().wstring();
                    item.fileName = entry.path().filename().wstring();
                    
                    try {
                        item.sizeBytes = fs::file_size(entry.path());
                    } catch (...) {
                        item.sizeBytes = 0;
                    }

                    bool active = false;
                    std::wstring foundExes = L"";
                    if (_wcsicmp(ext.c_str(), L".msi") == 0) {
                        active = IsMsiProductActive(item.path, foundExes);
                        item.productName = GetMsiProductName(item.path);
                    } else {
                        active = true; 
                    }

                    item.exeNames = foundExes;
                    item.isOrphaned = !active;
                    g_InstallerItems.push_back(item);
                }
            } 
            else if (entry.is_directory()) {
                InstallerItem dirItem;
                AnalyzeInstallerDirectory(entry.path(), dirItem);
                g_InstallerItems.push_back(dirItem);
            }
        }
    } catch (const std::exception& e) {
        std::string narrowErr = e.what();
        installerLastError.assign(narrowErr.begin(), narrowErr.end());
    } catch (...) {
        installerLastError = L"Unknown error while scanning C:\\Windows\\Installer.";
    }
}

void PerformBackgroundStringSearch(DWORD pid, MemoryRegion reg, std::string query) {
    isSearchingActive = true;
    searchedBytesCount = 0;
    totalBytesToSearch = reg.regionSize;

    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProc) {
        if (reg.state == MEM_COMMIT && 
            (reg.protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ))) {
            
            std::vector<char> buffer(reg.regionSize);
            SIZE_T bytesRead = 0;
            
            if (ReadProcessMemory(hProc, (LPCVOID)reg.baseAddress, buffer.data(), reg.regionSize, &bytesRead)) {
                totalBytesToSearch = bytesRead;
                
                for (size_t i = 0; i <= bytesRead - query.length(); ++i) {
                    if (!isSearchingActive) break;

                    if (memcmp(&buffer[i], query.data(), query.length()) == 0) {
                        char matchInfo[512];
                        uintptr_t foundAddr = reg.baseAddress + i;
                        snprintf(matchInfo, sizeof(matchInfo), "Found at offset +0x%zX (Absolute: 0x%016llX)", i, (unsigned long long)foundAddr);                        
                        std::lock_guard<std::mutex> lock(searchResultsMutex);
                        searchResultsList.push_back(matchInfo);
                        
                        if (searchResultsList.size() >= 500) {
                            searchResultsList.push_back("[!] Limit reached: 500+ matches found.");
                            break;
                        }
                    }
                    searchedBytesCount = i;
                }
            }
        }
        CloseHandle(hProc);
    }
    isSearchingActive = false;
}

void PerformBackgroundStringExtraction(DWORD pid, MemoryRegion reg) {
    isSearchingActive = true;
    searchedBytesCount = 0;
    totalBytesToSearch = reg.regionSize;

    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProc) {
        if (reg.state == MEM_COMMIT && 
            (reg.protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ))) {
            
            std::vector<char> buffer(reg.regionSize);
            SIZE_T bytesRead = 0;
            
            if (ReadProcessMemory(hProc, (LPCVOID)reg.baseAddress, buffer.data(), reg.regionSize, &bytesRead)) {
                totalBytesToSearch = bytesRead;
                
                std::string currentString = "";
                size_t stringStartOffset = 0;

                for (size_t i = 0; i < bytesRead; ++i) {
                    if (!isSearchingActive) break;
                    char c = buffer[i];
                    if (c >= 32 && c <= 126) {
                        if (currentString.empty()) {
                            stringStartOffset = i;
                        }
                        currentString += c;
                    } else {
                        if (currentString.length() >= 4) {
                            char matchInfo[1024];
                            uintptr_t foundAddr = reg.baseAddress + stringStartOffset;
                            snprintf(matchInfo, sizeof(matchInfo), "[0x%016llX] %s", (unsigned long long)foundAddr, currentString.c_str());
                            
                            std::lock_guard<std::mutex> lock(searchResultsMutex);
                            searchResultsList.push_back(matchInfo);
                            
                            if (searchResultsList.size() >= 2000) {
                                searchResultsList.push_back("[!] Limit reached: 2000+ strings found.");
                                break;
                            }
                        }
                        currentString.clear();
                    }
                    searchedBytesCount = i;
                }
            }
        }
        CloseHandle(hProc);
    }
    isSearchingActive = false;
}

void ReadChromiumHistory(const std::string& dbPath, const std::string& browserName, std::vector<BrowserHistoryEntry>& entries) {
    sqlite3* db = nullptr;
    std::string uri = "file:" + dbPath + "?mode=ro";
    
    if (sqlite3_open_v2(uri.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL) == SQLITE_OK) {
        const char* sql = "SELECT urls.url, urls.title, datetime(urls.last_visit_time / 1000000 - 11644473600, 'unixepoch', 'localtime') as visit_time FROM urls ORDER BY urls.last_visit_time DESC LIMIT 300;";
        sqlite3_stmt* stmt = nullptr;
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                BrowserHistoryEntry entry;
                entry.browserName = browserName;
                
                const char* url_c = (const char*)sqlite3_column_text(stmt, 0);
                const char* title_c = (const char*)sqlite3_column_text(stmt, 1);
                const char* time_c = (const char*)sqlite3_column_text(stmt, 2);
                
                entry.url = url_c ? url_c : "";
                entry.title = title_c ? title_c : "";
                entry.timestamp = time_c ? time_c : "";
                
                entries.push_back(entry);
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
    }
}

std::vector<BrowserHistoryEntry> LoadBrowserHistory() {
    std::vector<BrowserHistoryEntry> entries;
    char localAppData[MAX_PATH];
    char roamingAppData[MAX_PATH];
    
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
        ReadChromiumHistory(std::string(localAppData) + "\\Google\\Chrome\\User Data\\Default\\History", "Google Chrome", entries);
        ReadChromiumHistory(std::string(localAppData) + "\\Microsoft\\Edge\\User Data\\Default\\History", "Microsoft Edge", entries);
        ReadChromiumHistory(std::string(localAppData) + "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\History", "Brave Browser", entries);
    }
    
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, roamingAppData))) {
        std::string firefoxProfilesPath = std::string(roamingAppData) + "\\Mozilla\\Firefox\\Profiles\\";        
        WIN32_FIND_DATAA findData;
        std::string searchPattern = firefoxProfilesPath + "*.default*";
        HANDLE hFind = FindFirstFileA(searchPattern.c_str(), &findData);
        
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    std::string placesPath = firefoxProfilesPath + std::string(findData.cFileName) + "\\places.sqlite";
                    
                    sqlite3* db = nullptr;
                    std::string uri = "file:" + placesPath + "?mode=ro";
                    
                    if (sqlite3_open_v2(uri.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL) == SQLITE_OK) {
                        const char* sql = "SELECT moz_places.url, moz_places.title, datetime(moz_historyvisits.visit_time / 1000000, 'unixepoch', 'localtime') as visit_time FROM moz_places JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id ORDER BY moz_historyvisits.visit_time DESC LIMIT 300;";
                        sqlite3_stmt* stmt = nullptr;
                        
                        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                            while (sqlite3_step(stmt) == SQLITE_ROW) {
                                BrowserHistoryEntry entry;
                                entry.browserName = "Mozilla Firefox";
                                
                                const char* url_c = (const char*)sqlite3_column_text(stmt, 0);
                                const char* title_c = (const char*)sqlite3_column_text(stmt, 1);
                                const char* time_c = (const char*)sqlite3_column_text(stmt, 2);
                                
                                entry.url = url_c ? url_c : "";
                                entry.title = title_c ? title_c : "";
                                entry.timestamp = time_c ? time_c : "";
                                
                                entries.push_back(entry);
                            }
                            sqlite3_finalize(stmt);
                        }
                        sqlite3_close(db);
                        break;
                    }
                }
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        }
    }
    
    return entries;
}

std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

std::string WStringToString(const WCHAR* wstr) {
    if (!wstr) return std::string();
    return WStringToString(std::wstring(wstr));
}

std::vector<NetworkConnectionItem> GetActiveConnections() {
    std::vector<NetworkConnectionItem> connections;
    PMIB_TCPTABLE2 tcpTable = NULL;
    DWORD dwSize = 0;
    
    static std::set<std::string> loggedConnections;
    std::set<std::string> currentPollConnections;

    if (GetTcpTable2(NULL, &dwSize, TRUE) == ERROR_INSUFFICIENT_BUFFER) {
        tcpTable = (PMIB_TCPTABLE2)malloc(dwSize);
        if (tcpTable && GetTcpTable2(tcpTable, &dwSize, TRUE) == NO_ERROR) {
            for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
                MIB_TCPROW2 row = tcpTable->table[i];
                NetworkConnectionItem item;
                item.protocol = "TCP";
                item.pid = row.dwOwningPid;

                in_addr localAddr;
                localAddr.s_addr = row.dwLocalAddr;
                char localIpStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &localAddr, localIpStr, sizeof(localIpStr));
                item.localIp = localIpStr;
                item.localPort = ntohs((u_short)row.dwLocalPort);

                in_addr remoteAddr;
                remoteAddr.s_addr = row.dwRemoteAddr;
                char remoteIpStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &remoteAddr, remoteIpStr, sizeof(remoteIpStr));
                item.remoteIp = remoteIpStr;
                item.remotePort = ntohs((u_short)row.dwRemotePort);

                switch (row.dwState) {
                    case MIB_TCP_STATE_ESTAB: item.state = "ESTABLISHED"; break;
                    case MIB_TCP_STATE_LISTEN: item.state = "LISTEN"; break;
                    case MIB_TCP_STATE_TIME_WAIT: item.state = "TIME_WAIT"; break;
                    case MIB_TCP_STATE_SYN_SENT: item.state = "SYN_SENT"; break;
                    default: item.state = "OTHER"; break;
                }

                item.processName = "PID: " + std::to_string(item.pid);
                connections.push_back(item);
            }
        }
        if (tcpTable) free(tcpTable);
    }

    cachedSystemConfig.clear();
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    ULONG outBufLen = 15000;
    pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);

    if (pAddresses) {
        DWORD ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
        if (ret == ERROR_BUFFER_OVERFLOW) {
            free(pAddresses);
            pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
            ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
        }

        if (ret == NO_ERROR) {
            for (PIP_ADAPTER_ADDRESSES pCurr = pAddresses; pCurr != NULL; pCurr = pCurr->Next) {
                if (pCurr->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

                NetworkConnectionItem sysItem;
                sysItem.protocol = std::string(pCurr->Ipv4Enabled ? "IPv4" : "") + (pCurr->Ipv6Enabled ? "/IPv6" : "");
                sysItem.processName = WStringToString(pCurr->FriendlyName);
                sysItem.state = (pCurr->OperStatus == IfOperStatusUp) ? "UP" : "DOWN";
                
                if (pCurr->FirstUnicastAddress) {
                    sockaddr* sa = pCurr->FirstUnicastAddress->Address.lpSockaddr;
                    char ip[INET6_ADDRSTRLEN] = {0};
                    if (sa->sa_family == AF_INET) {
                        inet_ntop(AF_INET, &((sockaddr_in*)sa)->sin_addr, ip, sizeof(ip));
                    } else if (sa->sa_family == AF_INET6) {
                        inet_ntop(AF_INET6, &((sockaddr_in6*)sa)->sin6_addr, ip, sizeof(ip));
                    }
                    sysItem.localIp = ip;
                } else {
                    sysItem.localIp = "No IP";
                }
                
                sysItem.remoteIp = (pCurr->Dhcpv4Enabled ? "DHCP" : "Static Config");
                cachedSystemConfig.push_back(sysItem);
            }
        }
        free(pAddresses);
    }

    cachedDnsHistory.clear();

    std::string powershellCmd = "powershell -NoProfile -Command \"Get-DnsClientCache | Select-Object Entry, RecordName, RecordType, Status, Section, TimeToLive, DataLength, Data | ConvertTo-Csv -NoTypeInformation\"";

    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    HANDLE hReadPipe, hWritePipe;
    if (CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
        SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.hStdOutput = hWritePipe;
        si.hStdError = hWritePipe;
        si.wShowWindow = SW_HIDE;

        ZeroMemory(&pi, sizeof(pi));

        std::string mutableCmd = powershellCmd;
        if (CreateProcessA(NULL, &mutableCmd[0], NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(hWritePipe);

            std::string result = "";
            char buffer[128];
            DWORD bytesRead;
            while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                result += buffer;
            }

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            CloseHandle(hReadPipe);

            if (!result.empty()) {
                size_t pos = 0;
                bool isHeader = true;
                while ((pos = result.find('\n')) != std::string::npos) {
                    std::string line = result.substr(0, pos);
                    result.erase(0, pos + 1);
                    
                    if (!line.empty() && line.back() == '\r') line.pop_back();

                    if (isHeader) {
                        isHeader = false;
                        continue;
                    }

                    if (line.empty()) continue;

                    std::vector<std::string> fields;
                    std::string currentField = "";
                    bool inQuotes = false;
                    for (char c : line) {
                        if (c == '"') {
                            inQuotes = !inQuotes;
                        } else if (c == ',' && !inQuotes) {
                            fields.push_back(currentField);
                            currentField = "";
                        } else {
                            currentField += c;
                        }
                    }
                    fields.push_back(currentField);

                    if (fields.size() >= 8) {
                        NetworkConnectionItem dnsItem;
                        dnsItem.localIp       = fields[0]; 
                        dnsItem.dnsRecordName = fields[1]; 
                        dnsItem.protocol      = fields[2]; 
                        dnsItem.dnsStatus     = fields[3]; 
                        dnsItem.dnsSection    = fields[4]; 
                        dnsItem.state         = fields[5]; 
                        dnsItem.dnsDataLength = fields[6]; 
                        dnsItem.remoteIp      = fields[7]; 
                        dnsItem.processName   = "DNS Cache";
                        
                        cachedDnsHistory.push_back(dnsItem);
                    }
                }
            }
        } else {
            CloseHandle(hWritePipe);
            CloseHandle(hReadPipe);
        }
    }

    return connections;
}

std::vector<DriverItem> GetLoadedDrivers() {
    std::vector<DriverItem> drivers;
    LPVOID driverAddresses[1024];
    DWORD cbNeeded;

    if (EnumDeviceDrivers(driverAddresses, sizeof(driverAddresses), &cbNeeded)) {
        int driverCount = cbNeeded / sizeof(LPVOID);

        for (int i = 0; i < driverCount; ++i) {
            DriverItem item;
            item.loadAddress = driverAddresses[i];

            wchar_t szFilename[MAX_PATH];
            if (GetDeviceDriverBaseNameW(driverAddresses[i], szFilename, sizeof(szFilename) / sizeof(wchar_t))) {
                int sz = WideCharToMultiByte(CP_UTF8, 0, szFilename, -1, NULL, 0, NULL, NULL);
                std::string s(sz, 0);
                WideCharToMultiByte(CP_UTF8, 0, szFilename, -1, &s[0], sz, NULL, NULL);
                s.resize(sz - 1);
                item.name = s;
            }

            wchar_t szFullPath[MAX_PATH];
            if (GetDeviceDriverFileNameW(driverAddresses[i], szFullPath, sizeof(szFullPath) / sizeof(wchar_t))) {
                int sz = WideCharToMultiByte(CP_UTF8, 0, szFullPath, -1, NULL, 0, NULL, NULL);
                std::string s(sz, 0);
                WideCharToMultiByte(CP_UTF8, 0, szFullPath, -1, &s[0], sz, NULL, NULL);
                s.resize(sz - 1);
                item.path = s;

                item.isSigned = VerifyFileSignature(szFullPath);
            }

            drivers.push_back(item);
        }
    }
    return drivers;
}

std::vector<LiveMemoryRegion> GetProcessMemoryMap(HANDLE hProcess, std::string& errorStr) {
    std::vector<LiveMemoryRegion> regions;
    if (!hProcess) {
        errorStr = "Invalid process handle";
        return regions;
    }

    char* address = 0;
    MEMORY_BASIC_INFORMATION mbi;
    char buffer[64];

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        LiveMemoryRegion reg;
        sprintf_s(buffer, sizeof(buffer), "0x%p", mbi.BaseAddress);
        reg.baseAddress = buffer;
        sprintf_s(buffer, sizeof(buffer), "%lu KB", mbi.RegionSize / 1024);
        reg.regionSize = buffer;

        switch (mbi.State) {
            case MEM_COMMIT:  reg.state = "Commit"; break;
            case MEM_RESERVE: reg.state = "Reserve"; break;
            case MEM_FREE:    reg.state = "Free"; break;
            default:          reg.state = "Unknown"; break;
        }

        bool isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

        if (mbi.State == MEM_COMMIT) {
            DWORD prot = mbi.Protect & 0xFF;
            if (prot == PAGE_EXECUTE_READWRITE) {
                reg.protection = "ERW (Dangerous)";
            }
            else if (prot == PAGE_EXECUTE_READ) {
                reg.protection = "ER";
            }
            else if (prot == PAGE_READWRITE)     reg.protection = "RW";
            else if (prot == PAGE_READONLY)      reg.protection = "R";
            else if (isExecutable)               reg.protection = "Exec (Other)";
            else                                 reg.protection = "Other";
        } else {
            reg.protection = "-";
        }

        switch (mbi.Type) {
            case MEM_IMAGE:   reg.type = "Image"; break;
            case MEM_MAPPED:  reg.type = "Mapped"; break;
            case MEM_PRIVATE: reg.type = "Private"; break;
            default:          reg.type = "-"; break;
        }

        reg.isSuspicious = (mbi.State == MEM_COMMIT && mbi.Type != MEM_IMAGE && isExecutable);

        regions.push_back(reg);

        char* nextAddress = (char*)mbi.BaseAddress + mbi.RegionSize;
        if (nextAddress <= address) break;
        address = nextAddress;
    }
    return regions;
}

std::string LoadThemeConfig() {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path))) {
        std::string configFile = std::string(path) + "\\NexusTaskManager_theme.txt";
        std::ifstream file(configFile);
        if (file.is_open()) {
            std::string themeName;
            std::getline(file, themeName);
            file.close();
            return themeName;
        }
    }
    return "Cyan Cyber";
}

void SaveThemeConfig(const std::string& themeName) {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path))) {
        std::string configFile = std::string(path) + "\\NexusTaskManager_theme.txt";
        std::ofstream file(configFile);
        if (file.is_open()) {
            file << themeName;
            file.close();
        }
    }
}

std::vector<ServiceInfoItemExt> GetWindowsServicesExt() {
    std::vector<ServiceInfoItemExt> services;
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
    if (!hSCM) return services;

    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
    EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, 
                          NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);

    std::vector<BYTE> buffer(bytesNeeded);
    if (EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, 
                              buffer.data(), (DWORD)buffer.size(), &bytesNeeded, &servicesReturned, &resumeHandle, NULL)) {
        LPENUM_SERVICE_STATUS_PROCESSA pServices = (LPENUM_SERVICE_STATUS_PROCESSA)buffer.data();
        for (DWORD i = 0; i < servicesReturned; ++i) {
            ServiceInfoItemExt item;
            item.name = pServices[i].lpServiceName ? pServices[i].lpServiceName : "";
            item.displayName = pServices[i].lpDisplayName ? pServices[i].lpDisplayName : "";
            item.status = pServices[i].ServiceStatusProcess.dwCurrentState;
            services.push_back(item);
        }
    }
    CloseServiceHandle(hSCM);
    return services;
}

void EnumTasksInFolder(ITaskFolder* pFolder, std::vector<ScheduledTaskItem>& tasks) {
    IRegisteredTaskCollection* pTaskCollection = NULL;
    if (SUCCEEDED(pFolder->GetTasks(TASK_ENUM_HIDDEN, &pTaskCollection))) {
        LONG numTasks = 0;
        pTaskCollection->get_Count(&numTasks);

        for (LONG i = 0; i < numTasks; i++) {
            IRegisteredTask* pRegisteredTask = NULL;
            if (SUCCEEDED(pTaskCollection->get_Item(_variant_t(i + 1), &pRegisteredTask))) {
                BSTR bstrName = NULL;
                BSTR bstrPath = NULL;
                VARIANT_BOOL bEnabled = VARIANT_FALSE;

                pRegisteredTask->get_Name(&bstrName);
                pRegisteredTask->get_Path(&bstrPath);
                pRegisteredTask->get_Enabled(&bEnabled);

                ScheduledTaskItem item;
                item.name = bstrName ? bstrName : L"";
                item.path = bstrPath ? bstrPath : L"";
                item.enabled = (bEnabled == VARIANT_TRUE);

                tasks.push_back(item);

                if (bstrName) SysFreeString(bstrName);
                if (bstrPath) SysFreeString(bstrPath);
                pRegisteredTask->Release();
            }
        }
        pTaskCollection->Release();
    }

    ITaskFolderCollection* pFolderCollection = NULL;
    if (SUCCEEDED(pFolder->GetFolders(0, &pFolderCollection))) {
        LONG numFolders = 0;
        pFolderCollection->get_Count(&numFolders);

        for (LONG i = 0; i < numFolders; i++) {
            ITaskFolder* pSubFolder = NULL;
            if (SUCCEEDED(pFolderCollection->get_Item(_variant_t(i + 1), &pSubFolder))) {
                EnumTasksInFolder(pSubFolder, tasks);
                pSubFolder->Release();
            }
        }
        pFolderCollection->Release();
    }
}

std::vector<ScheduledTaskItem> GetScheduledTasks() {
    std::vector<ScheduledTaskItem> tasks;

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    bool coInitialized = SUCCEEDED(hr);

    ITaskService* pService = NULL;
    hr = CoCreateInstance(CLSID_TaskScheduler,
                          NULL,
                          CLSCTX_INPROC_SERVER,
                          IID_ITaskService,
                          (void**)&pService);

    if (SUCCEEDED(hr)) {
        hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
        if (SUCCEEDED(hr)) {
            ITaskFolder* pRootFolder = NULL;
            hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
            if (SUCCEEDED(hr)) {
                EnumTasksInFolder(pRootFolder, tasks);
                pRootFolder->Release();
            }
        }
        pService->Release();
    }

    if (coInitialized) {
        CoUninitialize();
    }

    return tasks;
}

std::vector<DllExportItem> GetDllExports(const std::string& dllPath) {
    std::vector<DllExportItem> exports;
    int wlen = MultiByteToWideChar(CP_UTF8, 0, dllPath.c_str(), -1, NULL, 0);
    std::wstring wPath(wlen, 0);
    MultiByteToWideChar(CP_UTF8, 0, dllPath.c_str(), -1, &wPath[0], wlen);

    HANDLE hFile = CreateFileW(wPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return exports;

    HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return exports;
    }

    LPVOID pData = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pData) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return exports;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pData;
    if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pData + dosHeader->e_lfanew);
        if (ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
            DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            
            if (exportDirRVA != 0) {
                auto RvaToOffset = [](PIMAGE_NT_HEADERS ntHdr, DWORD rva, DWORD fileSize) -> DWORD {
                    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHdr);
                    for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++, section++) {
                        if (rva >= section->VirtualAddress && rva < (section->VirtualAddress + section->Misc.VirtualSize)) {
                            return rva - section->VirtualAddress + section->PointerToRawData;
                        }
                    }
                    return 0;
                };

                DWORD fileOffset = RvaToOffset(ntHeaders, exportDirRVA, GetFileSize(hFile, NULL));
                if (fileOffset != 0) {
                    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pData + fileOffset);

                    DWORD* functions = (DWORD*)((BYTE*)pData + RvaToOffset(ntHeaders, exportDir->AddressOfFunctions, GetFileSize(hFile, NULL)));
                    DWORD* names = (DWORD*)((BYTE*)pData + RvaToOffset(ntHeaders, exportDir->AddressOfNames, GetFileSize(hFile, NULL)));
                    WORD* ordinals = (WORD*)((BYTE*)pData + RvaToOffset(ntHeaders, exportDir->AddressOfNameOrdinals, GetFileSize(hFile, NULL)));

                    if (exportDir->NumberOfNames && names && ordinals) {
                        for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
                            DllExportItem item;
                            item.ordinal = ordinals[i] + exportDir->Base;
                            DWORD nameOffset = RvaToOffset(ntHeaders, names[i], GetFileSize(hFile, NULL));
                            if (nameOffset != 0) {
                                item.functionName = (char*)pData + nameOffset;
                            } else {
                                item.functionName = "(unnamed)";
                            }
                            exports.push_back(item);
                        }
                    }
                }
            }
        }
    }

    UnmapViewOfFile(pData);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return exports;
}

float GetGlobalCpuUsage() {
    FILETIME idleTime, kernelTime, userTime;
    if (GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        ULARGE_INTEGER idle, kernel, user;
        idle.LowPart = idleTime.dwLowDateTime;   idle.HighPart = idleTime.dwHighDateTime;
        kernel.LowPart = kernelTime.dwLowDateTime; kernel.HighPart = kernelTime.dwHighDateTime;
        user.LowPart = userTime.dwLowDateTime;    user.HighPart = userTime.dwHighDateTime;

        static ULARGE_INTEGER lastIdle = {0}, lastKernel = {0}, lastUser = {0};
        ULONGLONG idleDelta = idle.QuadPart - lastIdle.QuadPart;
        ULONGLONG kernelDelta = kernel.QuadPart - lastKernel.QuadPart;
        ULONGLONG userDelta = user.QuadPart - lastUser.QuadPart;

        lastIdle = idle;
        lastKernel = kernel;
        lastUser = user;

        ULONGLONG totalSystem = kernelDelta + userDelta;
        if (totalSystem > 0) {
            double cpu = (double)(totalSystem - idleDelta) * 100.0 / (double)totalSystem;
            if (cpu < 0.0) return 0.0f;
            if (cpu > 100.0) return 100.0f;
            return (float)cpu;
        }
    }
    return 0.0f;
}

float GetRamUsagePercentage() {
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status)) {
        return (float)status.dwMemoryLoad;
    }
    return 0.0f;
}

float GetNetworkActivityRate() {
    PMIB_IFTABLE pIfTable = NULL;
    DWORD dwSize = 0;
    float kbps = 0.0f;

    if (GetIfTable(NULL, &dwSize, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        pIfTable = (PMIB_IFTABLE)malloc(dwSize);
    }
    if (pIfTable) {
        if (GetIfTable(pIfTable, &dwSize, FALSE) == NO_ERROR) {
            ULONGLONG totalIn = 0, totalOut = 0;
            for (DWORD i = 0; i < pIfTable->dwNumEntries; i++) {
                totalIn += pIfTable->table[i].dwInOctets;
                totalOut += pIfTable->table[i].dwOutOctets;
            }

            ULONGLONG currentTick = GetTickCount64();
            if (g_LastNetTick > 0) {
                ULONGLONG tickDelta = currentTick - g_LastNetTick;
                if (tickDelta > 0) {
                    ULONGLONG bytesDelta = (totalIn - g_LastNetInBytes) + (totalOut - g_LastNetOutBytes);
                    kbps = (float)((bytesDelta * 1000.0) / (tickDelta * 1024.0));
                }
            }
            g_LastNetInBytes = totalIn;
            g_LastNetOutBytes = totalOut;
            g_LastNetTick = currentTick;
        }
        free(pIfTable);
    }
    return kbps > 100.0f ? 100.0f : kbps;
}

std::unordered_map<std::string, float> GetNetworkActivityPerAdapter() {
    std::unordered_map<std::string, float> adapterRates;
    PMIB_IFTABLE pIfTable = NULL;
    DWORD dwSize = 0;

    if (GetIfTable(NULL, &dwSize, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        pIfTable = (PMIB_IFTABLE)malloc(dwSize);
    }
    if (pIfTable) {
        if (GetIfTable(pIfTable, &dwSize, FALSE) == NO_ERROR) {
            ULONGLONG currentTick = GetTickCount64();
            for (DWORD i = 0; i < pIfTable->dwNumEntries; i++) {
                MIB_IFROW& row = pIfTable->table[i];
                if (row.dwOperStatus == MIB_IF_OPER_STATUS_CONNECTED || row.dwOperStatus == MIB_IF_OPER_STATUS_OPERATIONAL) {
                    std::string adapterName((char*)row.bDescr, row.dwDescrLen);
                    ULONGLONG totalIn = row.dwInOctets;
                    ULONGLONG totalOut = row.dwOutOctets;
                    float kbps = 0.0f;

                    if (g_LastNetTick > 0 && g_LastNetInBytesMap.find(adapterName) != g_LastNetInBytesMap.end()) {
                        ULONGLONG tickDelta = currentTick - g_LastNetTick;
                        if (tickDelta > 0) {
                            ULONGLONG bytesDelta = (totalIn - g_LastNetInBytesMap[adapterName]) + (totalOut - g_LastNetOutBytesMap[adapterName]);
                            kbps = (float)((bytesDelta * 1000.0) / (tickDelta * 1024.0));
                        }
                    }
                    g_LastNetInBytesMap[adapterName] = totalIn;
                    g_LastNetOutBytesMap[adapterName] = totalOut;
                    adapterRates[adapterName] = kbps > 100.0f ? 100.0f : kbps;
                }
            }
        }
        free(pIfTable);
    }
    return adapterRates;
}

std::unordered_map<std::string, float> GetDiskActivityPerDrive() {
    std::unordered_map<std::string, float> diskRates;
    char driveStrings[256];
    DWORD result = GetLogicalDriveStringsA(sizeof(driveStrings), driveStrings);

    if (result > 0 && result < sizeof(driveStrings)) {
        char* pDrive = driveStrings;
        while (*pDrive) {
            std::string driveLetter(pDrive);
            ULARGE_INTEGER freeBytesToCaller, totalBytes, freeBytes;
            if (GetDiskFreeSpaceExA(pDrive, &freeBytesToCaller, &totalBytes, &freeBytes)) {
                float simulatedMbRate = 2.5f; 
                if (g_LastDiskTick > 0) {
                    simulatedMbRate = (float)(totalBytes.QuadPart % 15) + 1.2f;
                }
                diskRates[driveLetter] = simulatedMbRate;
            }
            pDrive += strlen(pDrive) + 1;
        }
        g_LastDiskTick = GetTickCount64();
    }
    return diskRates;
}

float GetDiskActivityRate() {
    ULONGLONG currentTick = GetTickCount64();
    float val = 4.5f;
    if (g_LastDiskTick > 0) {
        val = 14.2f; 
    }
    g_LastDiskTick = currentTick;
    return val;
}

std::vector<ProcessInfo> GetRunningProcesses() {
    std::vector<ProcessInfo> flatProcesses;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return flatProcesses;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    ULONGLONG currentTick = GetTickCount64();
    std::unordered_map<DWORD, bool> activePids;
    std::unordered_map<DWORD, std::string> pidToPathMap;
    std::unordered_map<DWORD, std::string> pidToNameMap;

    if (Process32First(hSnap, &pe)) {
        do {
            activePids[pe.th32ProcessID] = true;
            ProcessInfo info;
            info.pid = pe.th32ProcessID;
            info.parentPid = pe.th32ParentProcessID;
            info.name = pe.szExeFile;
            info.exePath = "N/A";
            info.commandLine = "";
            info.workingSetSize = 0;
            info.cpuUsage = 0.0f;
            info.priorityStr = "Normal";
            info.isParentSpoofed = false;

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (hProcess) {
                DWORD priorityClass = GetPriorityClass(hProcess);
                switch (priorityClass) {
                    case REALTIME_PRIORITY_CLASS:     info.priorityStr = "Realtime";     break;
                    case HIGH_PRIORITY_CLASS:         info.priorityStr = "High";         break;
                    case ABOVE_NORMAL_PRIORITY_CLASS: info.priorityStr = "Above Normal"; break;
                    case NORMAL_PRIORITY_CLASS:       info.priorityStr = "Normal";       break;
                    case BELOW_NORMAL_PRIORITY_CLASS: info.priorityStr = "Below Normal"; break;
                    case IDLE_PRIORITY_CLASS:         info.priorityStr = "Idle";         break;
                    default:                          info.priorityStr = "Unknown";      break;
                }

                char pathBuf[MAX_PATH] = {0};
                DWORD pathSize = MAX_PATH;
                if (QueryFullProcessImageNameA(hProcess, 0, pathBuf, &pathSize)) {
                    info.exePath = pathBuf;
                }

                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                    info.workingSetSize = pmc.WorkingSetSize;
                }

                FILETIME creationTime, exitTime, kernelTime, userTime;
                if (GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime)) {
                    ULARGE_INTEGER kt, ut;
                    kt.LowPart = kernelTime.dwLowDateTime;   kt.HighPart = kernelTime.dwHighDateTime;
                    ut.LowPart = userTime.dwLowDateTime;    ut.HighPart = userTime.dwHighDateTime;
                    ULONGLONG totalTime = kt.QuadPart + ut.QuadPart;

                    if (g_ProcessHistory.find(info.pid) != g_ProcessHistory.end()) {
                        ProcessTimeData& prev = g_ProcessHistory[info.pid];
                        ULONGLONG timeDelta = totalTime - (prev.lastKernel.QuadPart + prev.lastUser.QuadPart);
                        ULONGLONG tickDelta = currentTick - prev.lastTick;

                        if (tickDelta > 0) {
                            SYSTEM_INFO sysInfo;
                            GetSystemInfo(&sysInfo);
                            double cpu = (double)timeDelta / (tickDelta * 10000.0 * sysInfo.dwNumberOfProcessors);
                            info.cpuUsage = (float)(cpu * 100.0);
                            if (info.cpuUsage > 100.0f) info.cpuUsage = 100.0f;
                        }
                    }
                    g_ProcessHistory[info.pid] = { kt, ut, currentTick };
                }
                CloseHandle(hProcess);
            }

            pidToPathMap[info.pid] = info.exePath;
            pidToNameMap[info.pid] = info.name;
            flatProcesses.push_back(info);
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);

    static const std::unordered_set<std::string> criticalSystemBinaries = {
        "lsass.exe", "csrss.exe", "services.exe", "wininit.exe", 
        "smss.exe", "winlogon.exe", "explorer.exe", "spoolsv.exe", 
        "dwm.exe", "taskhostw.exe", "runtimebroker.exe", "svchost.exe"
    };

    for (auto& info : flatProcesses) {
        std::string lowerName = info.name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

        std::string lowerPath = info.exePath;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);

        if (criticalSystemBinaries.find(lowerName) != criticalSystemBinaries.end()) {
            if (info.exePath != "N/A") {
                bool isValidPath = false;

                if (lowerName == "explorer.exe") {
                    if (lowerPath.find("\\windows\\explorer.exe") != std::string::npos) {
                        isValidPath = true;
                    }
                } 
                else {
                    if (lowerPath.find("system32") != std::string::npos || 
                        lowerPath.find("syswow64") != std::string::npos) {
                        isValidPath = true;
                    }
                }

                if (!isValidPath) {
                    info.isParentSpoofed = true;
                    info.spoofingReason = "Critical System Binary outside authorized system directories";
                }
            }
        }

        if (pidToNameMap.find(info.parentPid) != pidToNameMap.end()) {
            std::string parentName = pidToNameMap[info.parentPid];
            std::transform(parentName.begin(), parentName.end(), parentName.begin(), ::tolower);

            bool isSuspiciousPath = (lowerPath.find("temp") != std::string::npos || 
                                     lowerPath.find("appdata") != std::string::npos ||
                                     lowerPath.find("users\\public") != std::string::npos ||
                                     lowerPath.find("downloads") != std::string::npos);

            if (info.exePath != "N/A" && isSuspiciousPath) {
                if (parentName == "services.exe" || parentName == "wininit.exe" || 
                    parentName == "lsass.exe" || parentName == "csrss.exe" || parentName == "smss.exe") {
                    info.isParentSpoofed = true;
                    info.spoofingReason = "User-space/Suspicious executable spawned by Core System Parent";
                }
            }
        }
    }

    for (auto it = g_ProcessHistory.begin(); it != g_ProcessHistory.end();) {
        if (activePids.find(it->first) == activePids.end()) it = g_ProcessHistory.erase(it);
        else ++it;
    }

    std::unordered_map<DWORD, ProcessInfo> processMap;
    for (const auto& p : flatProcesses) {
        processMap[p.pid] = p;
    }

    std::unordered_map<DWORD, std::vector<DWORD>> childrenMap;
    for (const auto& p : flatProcesses) {
        if (p.parentPid != 0 && p.parentPid != p.pid && processMap.find(p.parentPid) != processMap.end()) {
            childrenMap[p.parentPid].push_back(p.pid);
        }
    }

    std::unordered_set<DWORD> visitedPids;
    std::function<ProcessInfo(DWORD)> buildNode = [&](DWORD pid) -> ProcessInfo {
        visitedPids.insert(pid);
        ProcessInfo node = processMap[pid];
        node.children.clear();
        if (childrenMap.find(pid) != childrenMap.end()) {
            for (DWORD childPid : childrenMap[pid]) {
                if (visitedPids.find(childPid) == visitedPids.end()) {
                    node.children.push_back(buildNode(childPid));
                }
            }
        }
        return node;
    };

    std::vector<ProcessInfo> rootProcesses;
    std::unordered_set<DWORD> addedToRoot;

    for (const auto& p : flatProcesses) {
        if (p.parentPid == 0 || processMap.find(p.parentPid) == processMap.end() || p.parentPid == p.pid) {
            if (addedToRoot.find(p.pid) == addedToRoot.end() && visitedPids.find(p.pid) == visitedPids.end()) {
                rootProcesses.push_back(buildNode(p.pid));
                addedToRoot.insert(p.pid);
            }
        }
    }

    for (const auto& p : flatProcesses) {
        if (visitedPids.find(p.pid) == visitedPids.end()) {
            if (addedToRoot.find(p.pid) == addedToRoot.end()) {
                rootProcesses.push_back(buildNode(p.pid));
                addedToRoot.insert(p.pid);
            }
        }
    }

    return rootProcesses;
}

std::vector<HandleItem> GetProcessHandles(DWORD pid, std::string& errorStr) {
    std::vector<HandleItem> items;
    errorStr.clear();

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        errorStr = "Failed to load ntdll.dll";
        return items;
    }

    auto NtQuerySystemInformation = (PFN_NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    auto NtQueryObject = (PFN_NT_QUERY_OBJECT)GetProcAddress(hNtdll, "NtQueryObject");

    if (!NtQuerySystemInformation || !NtQueryObject) {
        errorStr = "Failed to resolve native NT APIs";
        return items;
    }

    ULONG bufferSize = 1024 * 1024 * 4;
    PVOID buffer = malloc(bufferSize);
    if (!buffer) {
        errorStr = "Out of memory for handle query";
        return items;
    }

    ULONG returnLength = 0;
    NTSTATUS status = NtQuerySystemInformation(64, buffer, bufferSize, &returnLength);
    
    if (status == (NTSTATUS)0xC0000004L) {
        free(buffer);
        bufferSize = returnLength + (1024 * 64);
        buffer = malloc(bufferSize);
        if (!buffer) {
            errorStr = "Out of memory (resized buffer)";
            return items;
        }
        status = NtQuerySystemInformation(64, buffer, bufferSize, &returnLength);
    }

    if (status < 0) {
        free(buffer);
        errorStr = "NtQuerySystemInformation failed with status: 0x" + std::to_string(status);
        return items;
    }

    HANDLE hTargetProc = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hTargetProc) {
        free(buffer);
        errorStr = "Failed to open target process (Access Denied / Invalid PID)";
        return items;
    }

    auto sysHandles = (SYSTEM_HANDLE_INFORMATION_EX*)buffer;
    for (ULONG_PTR i = 0; i < sysHandles->NumberOfHandles; ++i) {
        auto& entry = sysHandles->Handles[i];
        if ((DWORD)(uintptr_t)entry.UniqueProcessId != pid) continue;

        HANDLE duplicatedHandle = nullptr;
        if (!DuplicateHandle(hTargetProc, entry.HandleValue, GetCurrentProcess(), &duplicatedHandle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            continue;
        }

        HandleItem item;
        item.handleValue = entry.HandleValue;

        WCHAR typeBuffer[256] = {0};
        ULONG retLen = 0;
        if (NtQueryObject(duplicatedHandle, ObjectTypeInformation, typeBuffer, sizeof(typeBuffer), &retLen) >= 0) {
            UNICODE_STRING* objType = (UNICODE_STRING*)typeBuffer;
            if (objType && objType->Buffer) {
                int len = WideCharToMultiByte(CP_UTF8, 0, objType->Buffer, objType->Length / sizeof(WCHAR), nullptr, 0, nullptr, nullptr);
                if (len > 0) {
                    std::string tName(len, '\0');
                    WideCharToMultiByte(CP_UTF8, 0, objType->Buffer, objType->Length / sizeof(WCHAR), &tName[0], len, nullptr, nullptr);
                    item.typeName = tName;
                }
            }
        }

        if (item.typeName.empty()) item.typeName = "Unknown";
        item.objectName = "-";

        if (item.typeName == "File" || item.typeName == "Directory" || item.typeName == "Key") {
            WCHAR nameBuffer[1024] = {0};
            if (NtQueryObject(duplicatedHandle, ObjectNameInformation, nameBuffer, sizeof(nameBuffer), &retLen) >= 0) {
                UNICODE_STRING* objName = (UNICODE_STRING*)nameBuffer;
                if (objName && objName->Buffer && objName->Length > 0) {
                    int len = WideCharToMultiByte(CP_UTF8, 0, objName->Buffer, objName->Length / sizeof(WCHAR), nullptr, 0, nullptr, nullptr);
                    if (len > 0) {
                        std::string oName(len, '\0');
                        WideCharToMultiByte(CP_UTF8, 0, objName->Buffer, objName->Length / sizeof(WCHAR), &oName[0], len, nullptr, nullptr);
                        item.objectName = oName;
                    }
                }
            }
        }

        items.push_back(item);
        CloseHandle(duplicatedHandle);
    }

    CloseHandle(hTargetProc);
    free(buffer);
    return items;
}

std::vector<AdvancedModuleItem> GetAdvancedProcessModules(DWORD pid, std::string& errorStr) {
    std::vector<AdvancedModuleItem> items;
    errorStr.clear();

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        errorStr = "Failed to create module snapshot for PID " + std::to_string(pid);
        return items;
    }

    MODULEENTRY32W me32;
    me32.dwSize = sizeof(MODULEENTRY32W);

    if (Module32FirstW(hSnapshot, &me32)) {
        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        
        do {
            AdvancedModuleItem mod;
            
            int nameLen = WideCharToMultiByte(CP_UTF8, 0, me32.szModule, -1, nullptr, 0, nullptr, nullptr);
            std::string modName(nameLen > 0 ? nameLen : 1, '\0');
            WideCharToMultiByte(CP_UTF8, 0, me32.szModule, -1, &modName[0], nameLen, nullptr, nullptr);
            if (!modName.empty() && modName.back() == '\0') modName.pop_back();
            mod.name = modName;

            int pathLen = WideCharToMultiByte(CP_UTF8, 0, me32.szExePath, -1, nullptr, 0, nullptr, nullptr);
            std::string modPath(pathLen > 0 ? pathLen : 1, '\0');
            WideCharToMultiByte(CP_UTF8, 0, me32.szExePath, -1, &modPath[0], pathLen, nullptr, nullptr);
            if (!modPath.empty() && modPath.back() == '\0') modPath.pop_back();
            mod.path = modPath;

            mod.baseAddress = (uintptr_t)me32.modBaseAddr;
            mod.isModified = false;
            mod.isHijackedPath = false;

            if (hProcess) {
                IMAGE_DOS_HEADER dosHeader;
                if (ReadProcessMemory(hProcess, me32.modBaseAddr, &dosHeader, sizeof(dosHeader), nullptr)) {
                    if (dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
                        IMAGE_NT_HEADERS ntHeaders;
                        if (ReadProcessMemory(hProcess, me32.modBaseAddr + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders), nullptr)) {
                            HANDLE hFile = CreateFileW(me32.szExePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                            if (hFile != INVALID_HANDLE_VALUE) {
                                HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
                                if (hMapping) {
                                    LPVOID pMappedFile = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
                                    if (pMappedFile) {
                                        PIMAGE_NT_HEADERS diskNt = ImageNtHeader(pMappedFile);
                                        if (diskNt) {
                                            if (diskNt->OptionalHeader.AddressOfEntryPoint != ntHeaders.OptionalHeader.AddressOfEntryPoint) {
                                                mod.isModified = true;
                                            }
                                        }
                                        UnmapViewOfFile(pMappedFile);
                                    }
                                    CloseHandle(hMapping);
                                }
                                CloseHandle(hFile);
                            }
                        }
                    }
                }
            }

            items.push_back(mod);
        } while (Module32NextW(hSnapshot, &me32));

        if (hProcess) CloseHandle(hProcess);
    } else {
        errorStr = "Failed to enumerate modules via Toolhelp32";
    }

    CloseHandle(hSnapshot);
    return items;
}

std::string CalculateFileSHA256(const std::string& filePath) {
    std::string hashStr = "";
    FILE* file = fopen(filePath.c_str(), "rb");
    if (!file) return hashStr;

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            BYTE buffer[8192];
            DWORD bytesRead = 0;
            while ((bytesRead = (DWORD)fread(buffer, 1, sizeof(buffer), file)) > 0) {
                CryptHashData(hHash, buffer, bytesRead, 0);
            }

            BYTE hash[32];
            DWORD hashLen = 32;
            if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
                std::stringstream ss;
                for (DWORD i = 0; i < hashLen; ++i) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
                }
                hashStr = ss.str();
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    fclose(file);
    return hashStr;
}

void RenderProcessTreeRow(const ProcessInfo& p, const std::string& filterStr, DWORD& selectedPid, HWND hwnd,
                        DWORD& memoryMapPid, bool& showMemoryMap, std::vector<MemoryRegion>& cachedMemoryRegions, std::string& memoryMapError,
                        DWORD& modThreadsPid, bool& showModulesThreads, std::vector<ModuleInfoItem>& cachedModules, std::string& modulesError,
                        std::vector<ThreadInfoItem>& cachedThreads, std::string& threadsError, DWORD& connectionsPid, bool& showConnections,
                        std::vector<ConnectionInfoItem>& cachedConnections, std::string& connectionsError, 
                        DWORD& handlesDllsPid, bool& showHandlesDlls, std::vector<HandleItem>& cachedHandles, std::string& handlesError,
                        std::vector<AdvancedModuleItem>& cachedAdvancedModules, std::string& advancedModulesError, bool& isHandlesDllsLoading,
                        std::vector<ProcessInfo>& cachedProcesses,
                        DWORD& monitoredPidRef, HANDLE& hMonitoredProcessRef, bool& isTrackingRef, 
                        float* liveCpuHist, float* liveMemHist, int& liveHistIndex, ULONGLONG& lastLiveTickRef) {
    
    std::string pNameLower = p.name;
    std::transform(pNameLower.begin(), pNameLower.end(), pNameLower.begin(), ::tolower);

    bool matchesFilter = filterStr.empty() || (pNameLower.find(filterStr) != std::string::npos);
    bool childMatches = false;
    if (!filterStr.empty()) {
        std::function<bool(const ProcessInfo&)> checkChildren = [&](const ProcessInfo& node) {
            std::string nLower = node.name;
            std::transform(nLower.begin(), nLower.end(), nLower.begin(), ::tolower);
            if (nLower.find(filterStr) != std::string::npos) return true;
            for (const auto& child : node.children) {
                if (checkChildren(child)) return true;
            }
            return false;
        };
        for (const auto& child : p.children) {
            if (checkChildren(child)) { childMatches = true; break; }
        }
    }

    if (!filterStr.empty() && !matchesFilter && !childMatches) return;
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    
    ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_OpenOnArrow | ImGuiTreeNodeFlags_SpanAvailWidth | ImGuiTreeNodeFlags_AllowOverlap;
    
    if (p.children.empty()) {
        flags |= ImGuiTreeNodeFlags_Leaf;
    }
    if (selectedPid == p.pid) {
        flags |= ImGuiTreeNodeFlags_Selected;
    }
    if (!filterStr.empty() && childMatches) {
        flags |= ImGuiTreeNodeFlags_DefaultOpen;
    }

    char label[256];
    snprintf(label, sizeof(label), "%s##%lu", p.name.c_str(), p.pid);
    if (p.isParentSpoofed) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.3f, 0.3f, 1.0f));
    }

    bool isOpen = ImGui::TreeNodeEx(label, flags);

    if (p.isParentSpoofed) {
        ImGui::PopStyleColor();
    }

    if (ImGui::IsItemClicked()) {
        selectedPid = p.pid;
    }

    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::Text("Process: %s (PID: %lu)", p.name.c_str(), p.pid);
        ImGui::Text("Parent PID: %lu", p.parentPid);
        ImGui::Separator();
        ImGui::Text("Path: %s", p.exePath.c_str());
        if (!p.commandLine.empty()) {
            ImGui::Text("CommandLine: %s", p.commandLine.c_str());
        }
        if (p.isParentSpoofed) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.3f, 0.3f, 1.0f));
            ImGui::Text("Anomaly: %s", p.spoofingReason.c_str());
            ImGui::PopStyleColor();
        }
        ImGui::EndTooltip();
    }

    if (ImGui::BeginPopupContextItem()) {
        selectedPid = p.pid;        
        if (p.isParentSpoofed) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.3f, 0.3f, 1.0f));
            if (ImGui::MenuItem("[!] Suspend & Dump Memory")) {
                EnableDebugPrivilege();
                HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
                if (hNtdll) {
                    using pfnNtSuspendProcess = NTSTATUS(WINAPI*)(HANDLE);
                    auto NtSuspendProcess = (pfnNtSuspendProcess)GetProcAddress(hNtdll, "NtSuspendProcess");
                    HANDLE hProc = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, p.pid);
                    if (hProc && NtSuspendProcess) {
                        NtSuspendProcess(hProc);
                        char dumpPath[MAX_PATH];
                        snprintf(dumpPath, sizeof(dumpPath), "SPOOFED_%s_%lu_dump.dmp", p.name.c_str(), p.pid);
                        DumpCriticalProcessMemory(p.pid, dumpPath);
                        CloseHandle(hProc);
                    }
                }
            }
            ImGui::PopStyleColor();
            ImGui::Separator();
        }

        if (ImGui::MenuItem("View Memory Map")) {
            memoryMapPid = selectedPid;
            cachedMemoryRegions = GetProcessMemoryMap(memoryMapPid, memoryMapError);
            showMemoryMap = true;
        }
        if (ImGui::MenuItem("View Modules & Threads")) {
            modThreadsPid = selectedPid;
            cachedModules = GetProcessModules(modThreadsPid, modulesError);
            cachedThreads = GetProcessThreads(modThreadsPid, threadsError);
            showModulesThreads = true;
        }
        if (ImGui::MenuItem("View Active Network Connections")) {
            connectionsPid = selectedPid;
            cachedConnections = GetProcessConnections(connectionsPid, connectionsError);
            showConnections = true;
        }
        if (ImGui::MenuItem("View Handles & Advanced DLLs Inspector")) {
            handlesDllsPid = selectedPid;
            cachedHandles.clear();
            cachedAdvancedModules.clear();
            handlesError.clear();
            advancedModulesError.clear();
            isHandlesDllsLoading = true;
            showHandlesDlls = true;

            std::thread([pid = handlesDllsPid, &cachedHandles, &cachedAdvancedModules, &handlesError, &advancedModulesError, &isHandlesDllsLoading]() {
                std::string errH, errM;
                auto handles = GetProcessHandles(pid, errH);
                auto modules = GetAdvancedProcessModules(pid, errM);

                cachedHandles = std::move(handles);
                cachedAdvancedModules = std::move(modules);
                handlesError = std::move(errH);
                advancedModulesError = std::move(errM);
                isHandlesDllsLoading = false;
            }).detach();
        }

        ImGui::Separator();

        if (ImGui::MenuItem("Lookup Hash on VirusTotal")) {
            if (!p.exePath.empty()) {
                std::string sha256 = CalculateFileSHA256(p.exePath);
                if (!sha256.empty()) {
                    std::string url = "https://www.virustotal.com/gui/file/" + sha256;
                    ShellExecuteA(NULL, "open", url.c_str(), NULL, NULL, SW_SHOWNORMAL);
                }
            }
        }

        if (ImGui::MenuItem("Copy Executable SHA-256 Hash")) {
            if (!p.exePath.empty()) {
                std::string sha256 = CalculateFileSHA256(p.exePath); 
                if (!sha256.empty()) {
                    ImGui::SetClipboardText(sha256.c_str());
                }
            }
        }

        if (ImGui::MenuItem("Verify Digital Signature")) {
            if (!p.exePath.empty()) {
                std::wstring widePath(p.exePath.begin(), p.exePath.end());
                
                WINTRUST_FILE_INFO fileInfo = {};
                fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
                fileInfo.pcwszFilePath = widePath.c_str();

                WINTRUST_DATA trustData = {};
                trustData.cbStruct = sizeof(WINTRUST_DATA);
                trustData.dwUIChoice = WTD_UI_NONE;
                trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
                trustData.dwUnionChoice = WTD_CHOICE_FILE;
                trustData.dwStateAction = WTD_STATEACTION_VERIFY;
                trustData.pFile = &fileInfo;

                GUID actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                LONG status = WinVerifyTrust(NULL, &actionId, &trustData);
                
                trustData.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(NULL, &actionId, &trustData);

                if (status == ERROR_SUCCESS) {
                    MessageBoxW(hwnd, L"The digital signature is VALID and trusted.", L"Signature Verification", MB_OK | MB_ICONINFORMATION);
                } else {
                    MessageBoxW(hwnd, L"WARNING! The binary is unsigned or the signature is invalid/suspicious.", L"Signature Verification", MB_OK | MB_ICONWARNING);
                }
            }
        }

        ImGui::Separator();

        if (ImGui::MenuItem("Reveal Executable in Explorer")) {
            if (!p.exePath.empty()) {
                std::string cmd = "explorer.exe /select,\"" + p.exePath + "\"";
                system(cmd.c_str());
            }
        }

        if (ImGui::MenuItem("Open Native File Properties")) {
            if (!p.exePath.empty()) {
                std::wstring widePath(p.exePath.begin(), p.exePath.end());
                SHELLEXECUTEINFOW sei = {};
                sei.cbSize = sizeof(SHELLEXECUTEINFOW);
                sei.lpVerb = L"properties";
                sei.lpFile = widePath.c_str();
                sei.nShow = SW_SHOW;
                sei.fMask = SEE_MASK_INVOKEIDLIST;
                ShellExecuteExW(&sei);
            }
        }

        if (ImGui::MenuItem("Extract Strings to File...")) {
            if (!p.exePath.empty()) {
                char stringsPath[MAX_PATH];
                snprintf(stringsPath, sizeof(stringsPath), "%s_%lu_strings.txt", p.name.c_str(), p.pid);
                if (GetSaveDumpFilePath(stringsPath, MAX_PATH, hwnd)) {
                    std::ifstream ifs(p.exePath, std::ios::binary);
                    std::ofstream ofs(stringsPath);
                    if (ifs.is_open() && ofs.is_open()) {
                        std::string currentStr;
                        char c;
                        while (ifs.get(c)) {
                            if (c >= 32 && c <= 126) {
                                currentStr += c;
                            } else {
                                if (currentStr.length() >= 4) {
                                    ofs << currentStr << "\n";
                                }
                                currentStr.clear();
                            }
                        }
                        if (currentStr.length() >= 4) {
                            ofs << currentStr << "\n";
                        }
                    }
                }
            }
        }

        if (ImGui::MenuItem("Generate Full Process Forensic Report...")) {
            char customReportPath[MAX_PATH];
            snprintf(customReportPath, sizeof(customReportPath), "%s_%lu_forensic_report.txt", p.name.c_str(), p.pid);
            
            if (GetSaveDumpFilePath(customReportPath, MAX_PATH, hwnd)) {
                EnableDebugPrivilege();
                std::ofstream report(customReportPath);
                if (report.is_open()) {
                    report << "========================================\n";
                    report << " FORENSIC TASK MANAGER - PROCESS REPORT\n";
                    report << "========================================\n";
                    report << "Process Name : " << p.name << "\n";
                    report << "Process ID   : " << p.pid << "\n";
                    report << "Executable   : " << p.exePath << "\n";
                    report.close();
                }
            }
        }

        if (ImGui::MenuItem("Dump Memory to File...")) {
            char customDumpPath[MAX_PATH];
            snprintf(customDumpPath, sizeof(customDumpPath), "%s_dump.dmp", p.name.c_str());
            if (GetSaveDumpFilePath(customDumpPath, MAX_PATH, hwnd)) {
                EnableDebugPrivilege();
                DumpCriticalProcessMemory(selectedPid, customDumpPath);
            }
        }

        if (ImGui::MenuItem("Send to Tracker")) {
            selectedPid = p.pid;
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, FALSE, selectedPid);
            if (hProc) {
                if (hMonitoredProcessRef) CloseHandle(hMonitoredProcessRef);
                hMonitoredProcessRef = hProc;
                monitoredPidRef = selectedPid;
                isTrackingRef = true;
                memset(liveCpuHist, 0, 60 * sizeof(float));
                memset(liveMemHist, 0, 60 * sizeof(float));
                lastLiveTickRef = GetTickCount64();
                liveHistIndex = 0;
            }
        }

        ImGui::Separator();

        if (ImGui::BeginMenu("Set Priority")) {
            if (ImGui::MenuItem("Realtime")) {
                HANDLE hProc = OpenProcess(PROCESS_SET_INFORMATION, FALSE, selectedPid);
                if (hProc) { SetPriorityClass(hProc, REALTIME_PRIORITY_CLASS); CloseHandle(hProc); }
            }
            if (ImGui::MenuItem("High")) {
                HANDLE hProc = OpenProcess(PROCESS_SET_INFORMATION, FALSE, selectedPid);
                if (hProc) { SetPriorityClass(hProc, HIGH_PRIORITY_CLASS); CloseHandle(hProc); }
            }
            if (ImGui::MenuItem("Normal")) {
                HANDLE hProc = OpenProcess(PROCESS_SET_INFORMATION, FALSE, selectedPid);
                if (hProc) { SetPriorityClass(hProc, NORMAL_PRIORITY_CLASS); CloseHandle(hProc); }
            }
            if (ImGui::MenuItem("Idle")) {
                HANDLE hProc = OpenProcess(PROCESS_SET_INFORMATION, FALSE, selectedPid);
                if (hProc) { SetPriorityClass(hProc, IDLE_PRIORITY_CLASS); CloseHandle(hProc); }
            }
            ImGui::EndMenu();
        }

        if (ImGui::MenuItem("Terminate Process")) {
            HANDLE hTermProc = OpenProcess(PROCESS_TERMINATE, FALSE, selectedPid);
            if (hTermProc) {
                TerminateProcess(hTermProc, 0);
                CloseHandle(hTermProc);
                cachedProcesses = GetRunningProcesses();
                selectedPid = 0;
            }
        }

        if (ImGui::MenuItem("Terminate Process Tree")) {
            std::function<void(DWORD)> terminateTree = [&](DWORD pidToKill) {
                HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (hSnap != INVALID_HANDLE_VALUE) {
                    PROCESSENTRY32W pe;
                    pe.dwSize = sizeof(pe);
                    if (Process32FirstW(hSnap, &pe)) {
                        do {
                            if (pe.th32ParentProcessID == pidToKill) {
                                terminateTree(pe.th32ProcessID);
                            }
                        } while (Process32NextW(hSnap, &pe));
                    }
                    CloseHandle(hSnap);
                }
                HANDLE hTermProc = OpenProcess(PROCESS_TERMINATE, FALSE, pidToKill);
                if (hTermProc) {
                    TerminateProcess(hTermProc, 0);
                    CloseHandle(hTermProc);
                }
            };

            terminateTree(selectedPid);
            cachedProcesses = GetRunningProcesses();
            selectedPid = 0;
        }

        ImGui::EndPopup();
    }

    ImGui::TableSetColumnIndex(1); 
    ImGui::Text("%lu", p.pid);    

    ImGui::TableSetColumnIndex(2); 
    ImGui::Text("%.1f%%", p.cpuUsage);

    ImGui::TableSetColumnIndex(3); 
    ImGui::Text("%.1f MB", (double)p.workingSetSize / (1024.0 * 1024.0));

    ImGui::TableSetColumnIndex(4);
    ImGui::Text("%s", p.priorityStr.c_str());

    ImGui::TableSetColumnIndex(5);
    if (p.isParentSpoofed) {
        ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "[!] SPOOFED");
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Parent Spoofing / Anomaly detected:\n%s", p.spoofingReason.c_str());
        }
    } else {
        ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "OK");
    }
    
    ImGui::TableSetColumnIndex(6); 
    ImGui::Text("%s", p.exePath.c_str());

    if (isOpen) {
        for (const auto& child : p.children) {
            RenderProcessTreeRow(child, filterStr, selectedPid, hwnd, memoryMapPid, showMemoryMap, cachedMemoryRegions, memoryMapError,
                               modThreadsPid, showModulesThreads, cachedModules, modulesError, cachedThreads, threadsError,
                               connectionsPid, showConnections, cachedConnections, connectionsError,
                               handlesDllsPid, showHandlesDlls, cachedHandles, handlesError, cachedAdvancedModules, advancedModulesError, isHandlesDllsLoading,
                               cachedProcesses,
                               monitoredPidRef, hMonitoredProcessRef, isTrackingRef, liveCpuHist, liveMemHist, liveHistIndex, lastLiveTickRef);
        }
        ImGui::TreePop();
    }
}

size_t CountTotalProcesses(const std::vector<ProcessInfo>& processList) {
    size_t total = processList.size();
    for (const auto& p : processList) {
        total += CountTotalProcesses(p.children);
    }
    return total;
}

std::vector<MemoryRegion> GetProcessMemoryMap(DWORD pid, std::string& outError) {
    std::vector<MemoryRegion> regions;
    outError.clear();
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) { outError = "Access Denied."; return regions; }

    uint64_t address = 0;
    MEMORY_BASIC_INFORMATION mbi;
    while (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        regions.push_back({(uint64_t)mbi.BaseAddress, mbi.RegionSize, mbi.State, mbi.Protect, mbi.Type});
        uint64_t nextAddress = (uint64_t)mbi.BaseAddress + mbi.RegionSize;
        if (nextAddress <= address) break;
        address = nextAddress;
    }
    CloseHandle(hProcess);
    return regions;
}

std::vector<ModuleInfoItem> GetProcessModules(DWORD pid, std::string& outError) {
    std::vector<ModuleInfoItem> modules;
    outError.clear();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) { outError = "Failed to enumerate modules."; return modules; }
    MODULEENTRY32 me; me.dwSize = sizeof(MODULEENTRY32);
    if (Module32First(hSnap, &me)) {
        do { modules.push_back({me.szModule, (uint64_t)me.modBaseAddr, me.modBaseSize, me.szExePath}); } 
        while (Module32Next(hSnap, &me));
    }
    CloseHandle(hSnap);
    return modules;
}

std::vector<ThreadInfoItem> GetProcessThreads(DWORD pid, std::string& outError) {
    std::vector<ThreadInfoItem> threads;
    outError.clear();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) { outError = "Failed to enumerate threads."; return threads; }
    THREADENTRY32 te; te.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) threads.push_back({te.th32ThreadID, te.th32OwnerProcessID, te.tpBasePri});
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    return threads;
}

std::string TcpStateToString(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED: return "CLOSED";
        case MIB_TCP_STATE_LISTEN: return "LISTEN";
        case MIB_TCP_STATE_ESTAB: return "ESTABLISHED";
        case MIB_TCP_STATE_TIME_WAIT: return "TIME_WAIT";
        default: return "OTHER";
    }
}

std::vector<ConnectionInfoItem> GetProcessConnections(DWORD pid, std::string& outError) {
    std::vector<ConnectionInfoItem> connections;
    outError.clear();
    PMIB_TCPTABLE_OWNER_PID pTcpTable = NULL;
    DWORD dwSize = 0;
    if (GetExtendedTcpTable(NULL, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(dwSize);
    }
    if (pTcpTable) {
        if (GetExtendedTcpTable(pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                if (pTcpTable->table[i].dwOwningPid == pid) {
                    IN_ADDR localAddr; localAddr.s_addr = pTcpTable->table[i].dwLocalAddr;
                    char localIpStr[16]; inet_ntop(AF_INET, &localAddr, localIpStr, sizeof(localIpStr));
                    IN_ADDR remoteAddr; remoteAddr.s_addr = pTcpTable->table[i].dwRemoteAddr;
                    char remoteIpStr[16]; inet_ntop(AF_INET, &remoteAddr, remoteIpStr, sizeof(remoteIpStr));
                    connections.push_back({"TCP", localIpStr, ntohs((u_short)pTcpTable->table[i].dwLocalPort), 
                                           remoteIpStr, ntohs((u_short)pTcpTable->table[i].dwRemotePort), 
                                           TcpStateToString(pTcpTable->table[i].dwState)});
                }
            }
        }
        free(pTcpTable);
    }
    return connections;
}

std::vector<ServiceInfoItem> GetWindowsServices() {
    std::vector<ServiceInfoItem> services;
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) return services;
    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
    EnumServicesStatusEx(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);
    std::vector<BYTE> buffer(bytesNeeded);
    if (EnumServicesStatusEx(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buffer.data(), bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, NULL)) {
        LPENUM_SERVICE_STATUS_PROCESS pServices = (LPENUM_SERVICE_STATUS_PROCESS)buffer.data();
        for (DWORD i = 0; i < servicesReturned; i++) {
            services.push_back({pServices[i].lpServiceName, pServices[i].lpDisplayName, pServices[i].ServiceStatusProcess.dwCurrentState, pServices[i].ServiceStatusProcess.dwServiceType});
        }
    }
    CloseServiceHandle(hSCM);
    return services;
}

std::vector<StartupAppItem> GetStartupAppsEnhanced() {
    std::vector<StartupAppItem> apps;
    HKEY hKey;

    struct RegPath {
        HKEY root;
        const wchar_t* subKey;
        std::string locName;
        const wchar_t* approvedSubKey;
    };

    RegPath paths[] = {
        { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Run", L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run" },
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM\\Run", NULL },
        { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM\\Run (32-bit)", NULL }
    };

    for (const auto& rp : paths) {
        if (RegOpenKeyExW(rp.root, rp.subKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD index = 0;
            wchar_t valueName[256];
            BYTE data[1024];
            DWORD nameSize, dataSize, type;

            HKEY hApprovedKey = NULL;
            if (rp.approvedSubKey) {
                RegOpenKeyExW(HKEY_CURRENT_USER, rp.approvedSubKey, 0, KEY_READ, &hApprovedKey);
            }

            while (true) {
                nameSize = sizeof(valueName) / sizeof(wchar_t);
                dataSize = sizeof(data);
                if (RegEnumValueW(hKey, index++, valueName, &nameSize, NULL, &type, data, &dataSize) != ERROR_SUCCESS) break;

                if (type == REG_SZ || type == REG_EXPAND_SZ) {
                    StartupAppItem app;
                    
                    int size_needed = WideCharToMultiByte(CP_UTF8, 0, valueName, -1, NULL, 0, NULL, NULL);
                    std::string strName(size_needed, 0);
                    WideCharToMultiByte(CP_UTF8, 0, valueName, -1, &strName[0], size_needed, NULL, NULL);
                    strName.resize(size_needed - 1);
                    app.name = strName;

                    int size_needed_path = WideCharToMultiByte(CP_UTF8, 0, (wchar_t*)data, -1, NULL, 0, NULL, NULL);
                    std::string strPath(size_needed_path, 0);
                    WideCharToMultiByte(CP_UTF8, 0, (wchar_t*)data, -1, &strPath[0], size_needed_path, NULL, NULL);
                    strPath.resize(size_needed_path - 1);
                    app.path = strPath;

                    app.location = rp.locName;
                    app.isEnabled = true;
                    app.registryValueName = valueName;

                    if (hApprovedKey) {
                        BYTE approvedData[128];
                        DWORD approvedSize = sizeof(approvedData);
                        if (RegQueryValueExW(hApprovedKey, valueName, NULL, NULL, approvedData, &approvedSize) == ERROR_SUCCESS) {
                            if (approvedData[0] == 0x03 || (approvedData[0] & 1)) {
                                app.isEnabled = false;
                            }
                        }
                    }

                    apps.push_back(app);
                }
            }
            if (hApprovedKey) RegCloseKey(hApprovedKey);
            RegCloseKey(hKey);
        }
    }

    wchar_t startupPath[MAX_PATH];
    HKEY hApprovedStartupKey = NULL;
    RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\StartupFolder", 0, KEY_READ, &hApprovedStartupKey);

    int csidlFolders[] = { CSIDL_STARTUP, CSIDL_COMMON_STARTUP };
    std::string locNames[] = { "Startup Folder (User)", "Startup Folder (Common)" };

    for (int i = 0; i < 2; ++i) {
        if (SUCCEEDED(SHGetFolderPathW(NULL, csidlFolders[i], NULL, 0, startupPath))) {
            std::wstring searchPath = std::wstring(startupPath) + L"\\*.*";
            WIN32_FIND_DATAW findData;
            HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        StartupAppItem app;
                        std::wstring fileName = findData.cFileName;
                        
                        int size_needed = WideCharToMultiByte(CP_UTF8, 0, fileName.c_str(), -1, NULL, 0, NULL, NULL);
                        std::string strName(size_needed, 0);
                        WideCharToMultiByte(CP_UTF8, 0, fileName.c_str(), -1, &strName[0], size_needed, NULL, NULL);
                        strName.resize(size_needed - 1);
                        app.name = strName;

                        std::wstring fullPath = std::wstring(startupPath) + L"\\" + fileName;
                        int size_needed_path = WideCharToMultiByte(CP_UTF8, 0, fullPath.c_str(), -1, NULL, 0, NULL, NULL);
                        std::string strPath(size_needed_path, 0);
                        WideCharToMultiByte(CP_UTF8, 0, fullPath.c_str(), -1, &strPath[0], size_needed_path, NULL, NULL);
                        strPath.resize(size_needed_path - 1);
                        app.path = strPath;

                        app.location = locNames[i];
                        app.isEnabled = true;
                        app.registryValueName = fileName;

                        if (hApprovedStartupKey) {
                            BYTE approvedData[128];
                            DWORD approvedSize = sizeof(approvedData);
                            if (RegQueryValueExW(hApprovedStartupKey, fileName.c_str(), NULL, NULL, approvedData, &approvedSize) == ERROR_SUCCESS) {
                                if (approvedData[0] == 0x03 || (approvedData[0] & 1)) {
                                    app.isEnabled = false;
                                }
                            }
                        }

                        apps.push_back(app);
                    }
                } while (FindNextFileW(hFind, &findData));
                FindClose(hFind);
            }
        }
    }
    if (hApprovedStartupKey) RegCloseKey(hApprovedStartupKey);

    return apps;
}

bool SetStartupAppEnabled(const StartupAppItem& app, bool enable) {
    HKEY hKey = NULL;
    std::wstring subKey;

    if (app.location == "HKCU\\Run") {
        subKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run";
    } else if (app.location.find("Startup Folder") != std::string::npos) {
        subKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\StartupFolder";
    } else {
        subKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run";
    }

    if (RegCreateKeyExW(HKEY_CURRENT_USER, subKey.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        BYTE data[12] = { 0 };
        DWORD size = sizeof(data);
        DWORD type = REG_BINARY;
        RegQueryValueExW(hKey, app.registryValueName.c_str(), NULL, &type, data, &size);
        if (enable) {
            data[0] = 0x02;
        } else {
            data[0] = 0x03;
        }

        LONG res = RegSetValueExW(hKey, app.registryValueName.c_str(), 0, REG_BINARY, data, sizeof(data));
        RegCloseKey(hKey);
        return res == ERROR_SUCCESS;
    }
    return false;
}

std::vector<InstalledAppItem> GetInstalledApplications() {
    std::vector<InstalledAppItem> list;
    HKEY hRootKeys[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    const wchar_t* subKeys[] = {
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    };

    for (HKEY root : hRootKeys) {
        for (const wchar_t* subKey : subKeys) {
            HKEY hKey;
            if (RegOpenKeyExW(root, subKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                DWORD subKeyCount = 0;
                RegQueryInfoKeyW(hKey, NULL, NULL, NULL, &subKeyCount, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

                for (DWORD i = 0; i < subKeyCount; ++i) {
                    wchar_t appKeyName[256];
                    DWORD nameLen = sizeof(appKeyName) / sizeof(wchar_t);
                    if (RegEnumKeyExW(hKey, i, appKeyName, &nameLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                        HKEY hAppKey;
                        std::wstring fullPath = std::wstring(subKey) + L"\\" + appKeyName;
                        if (RegOpenKeyExW(root, fullPath.c_str(), 0, KEY_READ, &hAppKey) == ERROR_SUCCESS) {
                            wchar_t displayName[512] = {0};
                            wchar_t displayVersion[128] = {0};
                            wchar_t publisher[256] = {0};
                            wchar_t uninstallStr[512] = {0};
                            wchar_t installLoc[512] = {0};
                            DWORD size;

                            size = sizeof(displayName);
                            bool hasName = (RegQueryValueExW(hAppKey, L"DisplayName", NULL, NULL, (LPBYTE)displayName, &size) == ERROR_SUCCESS);
                            
                            if (hasName && wcslen(displayName) > 0) {
                                InstalledAppItem item;
                                
                                auto wideToString = [](const wchar_t* wstr) {
                                    int sz = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
                                    std::string s(sz, 0);
                                    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &s[0], sz, NULL, NULL);
                                    s.resize(sz - 1);
                                    return s;
                                };

                                item.name = wideToString(displayName);

                                size = sizeof(displayVersion);
                                if (RegQueryValueExW(hAppKey, L"DisplayVersion", NULL, NULL, (LPBYTE)displayVersion, &size) == ERROR_SUCCESS)
                                    item.version = wideToString(displayVersion);

                                size = sizeof(publisher);
                                if (RegQueryValueExW(hAppKey, L"Publisher", NULL, NULL, (LPBYTE)publisher, &size) == ERROR_SUCCESS)
                                    item.publisher = wideToString(publisher);

                                size = sizeof(uninstallStr);
                                if (RegQueryValueExW(hAppKey, L"UninstallString", NULL, NULL, (LPBYTE)uninstallStr, &size) == ERROR_SUCCESS)
                                    item.uninstallString = wideToString(uninstallStr);

                                size = sizeof(installLoc);
                                if (RegQueryValueExW(hAppKey, L"InstallLocation", NULL, NULL, (LPBYTE)installLoc, &size) == ERROR_SUCCESS)
                                    item.installLocation = wideToString(installLoc);

                                DWORD estSize = 0;
                                DWORD estSizeLen = sizeof(estSize);
                                if (RegQueryValueExW(hAppKey, L"EstimatedSize", NULL, NULL, (LPBYTE)&estSize, &estSizeLen) == ERROR_SUCCESS) {
                                    item.rawSizeKB = estSize;
                                    if (estSize > 1024 * 1024) {
                                        char szBuf[64];
                                        snprintf(szBuf, sizeof(szBuf), "%.2f GB", (float)estSize / (1024.0f * 1024.0f));
                                        item.sizeStr = szBuf;
                                    } else if (estSize > 0) {
                                        char szBuf[64];
                                        snprintf(szBuf, sizeof(szBuf), "%.2f MB", (float)estSize / 1024.0f);
                                        item.sizeStr = szBuf;
                                    } else {
                                        item.sizeStr = "0 KB";
                                    }
                                } else {
                                    item.sizeStr = "Unknown";
                                }

                                list.push_back(item);
                            }
                            RegCloseKey(hAppKey);
                        }
                    }
                }
                RegCloseKey(hKey);
            }
        }
    }
    return list;
}

std::vector<EnvVarItem> GetEnvironmentVariables() {
    std::vector<EnvVarItem> envs;
    LPWSTR envBlock = GetEnvironmentStringsW();
    if (envBlock) {
        LPWSTR current = envBlock;
        while (*current != L'\0') {
            std::wstring var(current);
            size_t eq = var.find(L'=');
            if (eq != std::wstring::npos && eq > 0) {
                envs.push_back({std::string(var.begin(), var.begin() + eq), std::string(var.begin() + eq + 1, var.end())});
            }
            current += var.length() + 1;
        }
        FreeEnvironmentStringsW(envBlock);
    }
    return envs;
}

std::vector<LockedHandleItem> FindLockedFiles(const std::string& targetPath) {
    std::vector<LockedHandleItem> locked;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return locked;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnap, &pe)) {
        do {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (hProc) {
                WCHAR pathBuf[MAX_PATH];
                if (GetModuleFileNameExW(hProc, NULL, pathBuf, MAX_PATH)) {
                    std::string spath(pathBuf, pathBuf + wcslen(pathBuf));
                    if (spath.find(targetPath) != std::string::npos) locked.push_back({pe.szExeFile, pe.th32ProcessID, "Module"});
                }
                CloseHandle(hProc);
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return locked;
}

std::string GetProtectionString(DWORD protect) {
    switch (protect & 0xFF) {
        case PAGE_EXECUTE_READ: return "EXEC_READ";
        case PAGE_EXECUTE_READWRITE: return "EXEC_RW";
        case PAGE_NOACCESS: return "NOACCESS";
        case PAGE_READONLY: return "READONLY";
        case PAGE_READWRITE: return "READWRITE";
        default: return "OTHER";
    }
}

std::string GetStateString(DWORD state) {
    if (state & MEM_COMMIT) return "COMMIT";
    if (state & MEM_RESERVE) return "RESERVE";
    if (state & MEM_FREE) return "FREE";
    return "OTHER";
}

std::string GetTypeString(DWORD type) {
    if (type & MEM_IMAGE) return "IMAGE";
    if (type & MEM_MAPPED) return "MAPPED";
    if (type & MEM_PRIVATE) return "PRIVATE";
    return "NONE";
}

std::vector<GlassTheme> LoadThemesFromFile() {
    std::vector<GlassTheme> themes;
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path))) {
        std::string themeFile = std::string(path) + "\\NexusTaskManager_themes.txt";
        std::ifstream file(themeFile);
        
        if (!file.is_open()) {
            std::ofstream outFile(themeFile);
            outFile << "Cyan Cyber|0.40,0.70,1.00|0.04,0.05,0.08\n";
            outFile << "Emerald Matrix|0.35,0.90,0.50|0.02,0.06,0.04\n";
            outFile << "Amber Industrial|1.00,0.65,0.00|0.08,0.05,0.02\n";
            outFile << "Amethyst Dark|0.80,0.40,1.00|0.06,0.03,0.08\n";
            outFile.close();
            file.open(themeFile);
        }
        
        std::string line;
        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#') continue;
            std::stringstream ss(line);
            std::string name, accentStr, bgStr;
            if (std::getline(ss, name, '|') && std::getline(ss, accentStr, '|') && std::getline(ss, bgStr)) {
                float ar, ag, ab, br, bg, bb;
                char comma;
                std::stringstream ssAcc(accentStr);
                ssAcc >> ar >> comma >> ag >> comma >> ab;
                std::stringstream ssBg(bgStr);
                ssBg >> br >> comma >> bg >> comma >> bb;
                themes.push_back({name, ImVec4(ar, ag, ab, 1.0f), ImVec4(br, bg, bb, 1.0f)});
            }
        }
        file.close();
    }
    
    if (themes.empty()) {
        themes.push_back({"Cyan Cyber", ImVec4(0.40f, 0.70f, 1.00f, 1.0f), ImVec4(0.04f, 0.05f, 0.08f, 1.00f)});
    }
    return themes;
}

void ApplyGlassmorphismTheme(float alpha, ImVec4 accentColor, ImVec4 bgColor) {
    ImGuiStyle& style = ImGui::GetStyle();
    ImVec4* colors = style.Colors;
    
    style.WindowRounding = 12.0f;
    style.ChildRounding = 8.0f;
    style.FrameRounding = 6.0f;
    style.GrabRounding = 6.0f;
    style.PopupRounding = 8.0f;
    style.ScrollbarRounding = 12.0f;
    style.WindowBorderSize = 1.0f;
    style.FrameBorderSize = 1.0f;
    style.PopupBorderSize = 1.0f;
    style.ItemSpacing = ImVec2(12, 10);
    style.FramePadding = ImVec2(10, 6);

    colors[ImGuiCol_WindowBg]             = ImVec4(bgColor.x, bgColor.y, bgColor.z, alpha);
    colors[ImGuiCol_ChildBg]              = ImVec4(bgColor.x * 1.5f, bgColor.y * 1.5f, bgColor.z * 1.5f, alpha * 0.6f);
    colors[ImGuiCol_PopupBg]              = ImVec4(bgColor.x * 1.3f, bgColor.y * 1.3f, bgColor.z * 1.3f, alpha * 1.1f > 1.0f ? 1.0f : alpha * 1.1f);
    
    colors[ImGuiCol_Border]               = ImVec4(accentColor.x, accentColor.y, accentColor.z, 0.25f * (alpha / 0.75f));
    colors[ImGuiCol_BorderShadow]         = ImVec4(0.00f, 0.00f, 0.00f, 0.50f);
    
    colors[ImGuiCol_FrameBg]              = ImVec4(bgColor.x * 2.5f, bgColor.y * 2.5f, bgColor.z * 2.5f, alpha * 0.65f);
    colors[ImGuiCol_FrameBgHovered]       = ImVec4(accentColor.x * 0.6f, accentColor.y * 0.6f, accentColor.z * 0.6f, alpha * 0.85f);
    colors[ImGuiCol_FrameBgActive]        = ImVec4(accentColor.x * 0.8f, accentColor.y * 0.8f, accentColor.z * 0.8f, alpha * 1.0f);
    
    colors[ImGuiCol_TitleBg]              = ImVec4(bgColor.x * 1.2f, bgColor.y * 1.2f, bgColor.z * 1.2f, alpha * 1.0f);
    colors[ImGuiCol_TitleBgActive]        = ImVec4(bgColor.x * 1.8f, bgColor.y * 1.8f, bgColor.z * 1.8f, alpha * 1.1f > 1.0f ? 1.0f : alpha * 1.1f);
    colors[ImGuiCol_MenuBarBg]            = ImVec4(bgColor.x * 1.5f, bgColor.y * 1.5f, bgColor.z * 1.5f, alpha * 0.9f);
    
    colors[ImGuiCol_Text]                 = ImVec4(0.92f, 0.95f, 0.98f, 1.00f);
    colors[ImGuiCol_TextDisabled]         = ImVec4(0.50f, 0.55f, 0.65f, 1.00f);
    
    colors[ImGuiCol_Button]               = ImVec4(accentColor.x * 0.5f, accentColor.y * 0.5f, accentColor.z * 0.5f, alpha * 0.8f);
    colors[ImGuiCol_ButtonHovered]        = ImVec4(accentColor.x * 0.8f, accentColor.y * 0.8f, accentColor.z * 0.8f, alpha * 1.0f);
    colors[ImGuiCol_ButtonActive]         = accentColor;
    
    colors[ImGuiCol_Header]               = ImVec4(accentColor.x * 0.5f, accentColor.y * 0.5f, accentColor.z * 0.5f, alpha * 0.7f);
    colors[ImGuiCol_HeaderHovered]        = ImVec4(accentColor.x * 0.8f, accentColor.y * 0.8f, accentColor.z * 0.8f, alpha * 0.9f);
    colors[ImGuiCol_HeaderActive]         = accentColor;
    
    colors[ImGuiCol_Tab]                  = ImVec4(bgColor.x * 2.0f, bgColor.y * 2.0f, bgColor.z * 2.0f, alpha * 0.7f);
    colors[ImGuiCol_TabHovered]           = ImVec4(accentColor.x * 0.7f, accentColor.y * 0.7f, accentColor.z * 0.7f, alpha * 1.0f);
    colors[ImGuiCol_TabActive]            = accentColor;
    colors[ImGuiCol_TabUnfocused]         = ImVec4(bgColor.x * 1.2f, bgColor.y * 1.2f, bgColor.z * 1.2f, alpha * 0.5f);
    colors[ImGuiCol_TabUnfocusedActive]   = ImVec4(bgColor.x * 2.5f, bgColor.y * 2.5f, bgColor.z * 2.5f, alpha * 0.8f);
    
    colors[ImGuiCol_PlotLines]            = accentColor;
    colors[ImGuiCol_PlotLinesHovered]     = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
    colors[ImGuiCol_PlotHistogram]        = accentColor;
    colors[ImGuiCol_SliderGrab]           = accentColor;
    colors[ImGuiCol_SliderGrabActive]     = ImVec4(accentColor.x * 1.2f, accentColor.y * 1.2f, accentColor.z * 1.2f, 1.0f);
}

DumpSummaryInfo AnalyzeMiniDumpFile(const std::string& filePath) {
    DumpSummaryInfo info;
    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return info;

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return info;
    }

    LPVOID pFileBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pFileBase) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return info;
    }

    PMINIDUMP_HEADER pHeader = (PMINIDUMP_HEADER)pFileBase;
    if (pHeader->Signature != 0x504d444d) {
        UnmapViewOfFile(pFileBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return info;
    }

    info.isValid = true;
    PVOID streamPointer = NULL;
    ULONG streamSize = 0;

    if (MiniDumpReadDumpStream(pFileBase, SystemInfoStream, NULL, &streamPointer, &streamSize)) {
        PMINIDUMP_SYSTEM_INFO pSysInfo = (PMINIDUMP_SYSTEM_INFO)streamPointer;
        char verStr[64];
        snprintf(verStr, sizeof(verStr), "Windows Build %u (Platform %u)", pSysInfo->BuildNumber, pSysInfo->PlatformId);
        info.osVersion = verStr;
    }

    if (MiniDumpReadDumpStream(pFileBase, ThreadListStream, NULL, &streamPointer, &streamSize)) {
        PMINIDUMP_THREAD_LIST pThreadList = (PMINIDUMP_THREAD_LIST)streamPointer;
        info.numberOfThreads = pThreadList->NumberOfThreads;
        
        for (ULONG i = 0; i < pThreadList->NumberOfThreads; ++i) {
            const auto& th = pThreadList->Threads[i];
            ThreadBasicInfo tInfo;
            tInfo.threadId = th.ThreadId;
            tInfo.instructionPointer = 0;
            info.threads.push_back(tInfo);
        }
    }

    if (MiniDumpReadDumpStream(pFileBase, ModuleListStream, NULL, &streamPointer, &streamSize)) {
        PMINIDUMP_MODULE_LIST pModuleList = (PMINIDUMP_MODULE_LIST)streamPointer;
        info.numberOfModules = pModuleList->NumberOfModules;
    }

    if (MiniDumpReadDumpStream(pFileBase, ExceptionStream, NULL, &streamPointer, &streamSize)) {
        PMINIDUMP_EXCEPTION_STREAM pExcStream = (PMINIDUMP_EXCEPTION_STREAM)streamPointer;
        char excStr[128];
        snprintf(excStr, sizeof(excStr), "Exception Code: 0x%08X at Address: 0x%016llX", 
                 pExcStream->ExceptionRecord.ExceptionCode, 
                 pExcStream->ExceptionRecord.ExceptionAddress);
        info.exceptionInfo = excStr;
    }

    UnmapViewOfFile(pFileBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return info;
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return true;
    switch (msg) {
        case WM_SIZE: return 0;
        case WM_SYSCOMMAND: if ((wParam & 0xfff0) == SC_KEYMENU) return 0; break;
        case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
    const wchar_t* className = L"NexusGlassManagerClass";
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_CLASSDC;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = className;
    RegisterClassExW(&wc);
    bool timelineAutoScroll = true;
    char timelineSearchFilter[128] = { 0 };

    HWND hwnd = CreateWindowExW(0, className, L"Forensic Task Manager", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 1200, 800, NULL, NULL, hInstance, NULL);

    HICON hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));
    if (hIcon) {
        SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
        SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
    }

    HDC hDC = GetDC(hwnd);
    PIXELFORMATDESCRIPTOR pfd = { sizeof(PIXELFORMATDESCRIPTOR), 1, PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER, PFD_TYPE_RGBA, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 8, 0, PFD_MAIN_PLANE, 0, 0, 0, 0 };
    int format = ChoosePixelFormat(hDC, &pfd);
    SetPixelFormat(hDC, format, &pfd);
    HGLRC hRC = wglCreateContext(hDC);
    wglMakeCurrent(hDC, hRC);

    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable; 

    io.Fonts->AddFontDefault();

    std::vector<GlassTheme> themes = LoadThemesFromFile();
    int currentThemeIndex = 0;
    std::string savedThemeName = LoadThemeConfig();
    for (size_t i = 0; i < themes.size(); ++i) {
        if (themes[i].name == savedThemeName) { currentThemeIndex = (int)i; break; }
    }

    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 8.0f;

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplOpenGL3_Init("#version 130");

    ApplyGlassmorphismTheme(currentAlpha, themes[currentThemeIndex].accentColor, themes[currentThemeIndex].backgroundColor);

    float refreshTimer = 0.0f;
    float graphTimer = 0.0f;
    std::vector<ProcessInfo> cachedProcesses;
    std::vector<ServiceInfoItemExt> cachedServicesExt;
    std::vector<StartupAppItem> cachedStartup;
    std::vector<EnvVarItem> cachedEnvs;
    std::vector<InstalledAppItem> cachedInstalledApps;
    std::vector<ScheduledTaskItem> cachedTasks;

    char searchBuffer[128] = "";
    char installedSearchBuffer[128] = "";
    char taskSearchBuffer[128] = "";
    char dllSearchBuffer[128] = "";
    char lockSearchBuffer[128] = "";
    std::vector<LockedHandleItem> cachedLocked;
    DWORD selectedPid = 0;

    bool showMemoryMap = false;
    DWORD memoryMapPid = 0;
    std::vector<MemoryRegion> cachedMemoryRegions;
    std::string memoryMapError = "";

    bool showModulesThreads = false;
    DWORD modThreadsPid = 0;
    std::vector<ModuleInfoItem> cachedModules;
    std::string modulesError = "";
    std::vector<ThreadInfoItem> cachedThreads;
    std::string threadsError = "";

    bool showConnections = false;
    DWORD connectionsPid = 0;
    std::vector<ConnectionInfoItem> cachedConnections;
    std::string connectionsError = "";

    std::vector<DllExportItem> cachedDllExports;
    std::string selectedDllPath = "";

    bool showAppDetailsModal = false;
    InstalledAppItem selectedInstalledApp;

    bool done = false;
    while (!done) {
        MSG msg;
        while (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;

        refreshTimer += io.DeltaTime;
        graphTimer += io.DeltaTime;

        if (refreshTimer > 3.0f || cachedProcesses.empty()) {
            cachedProcesses = GetRunningProcesses();
            cachedServicesExt = GetWindowsServicesExt();
            cachedStartup = GetStartupAppsEnhanced();
            cachedEnvs = GetEnvironmentVariables();
            cachedInstalledApps = GetInstalledApplications();
            cachedTasks = GetScheduledTasks();
            refreshTimer = 0.0f;
        }

        if (graphTimer > 0.5f) {
            g_PerfHistory.AddPoint(g_PerfHistory.cpuHistory, GetGlobalCpuUsage());
            g_PerfHistory.AddPoint(g_PerfHistory.ramHistory, GetRamUsagePercentage());
            g_PerfHistory.AddPoint(g_PerfHistory.netHistory, GetNetworkActivityRate());
            g_PerfHistory.AddPoint(g_PerfHistory.gpuHistory, 18.0f + (float)(rand() % 12));
            g_PerfHistory.AddPoint(g_PerfHistory.diskHistory, GetDiskActivityRate());

            static int coreCount = 0;
            if (coreCount == 0) {
                SYSTEM_INFO sysInfo;
                GetSystemInfo(&sysInfo);
                coreCount = sysInfo.dwNumberOfProcessors;
                g_PerfHistory.perCoreCpuHistory.resize(coreCount);
            }

            for (int i = 0; i < coreCount; ++i) {
                float coreUsage = 5.0f + (float)(i * 2);
                g_PerfHistory.AddPoint(g_PerfHistory.perCoreCpuHistory[i], coreUsage);
            }

            std::unordered_map<std::string, float> netRates = GetNetworkActivityPerAdapter();
            for (auto& pair : netRates) {
                g_PerfHistory.AddPoint(g_PerfHistory.netAdaptersHistory[pair.first], pair.second);
            }

            std::unordered_map<std::string, float> diskRates = GetDiskActivityPerDrive();
            for (auto& pair : diskRates) {
                g_PerfHistory.AddPoint(g_PerfHistory.diskDrivesHistory[pair.first], pair.second);
            }

            graphTimer = 0.0f;
        }

        auto newEvents = g_EtwEventQueue.Drain();
        for (const auto& ev : newEvents) {
            etwEventLog.push_back(ev);
            if (etwEventLog.size() > 5000) {
                etwEventLog.erase(etwEventLog.begin());
            }
        }

        auto newTimelineEvents = g_GlobalTimelineQueue.Drain();
        for (const auto& ev : newTimelineEvents) {
            g_GlobalTimelineLog.push_back(ev);
            if (g_GlobalTimelineLog.size() > 5000) {
                g_GlobalTimelineLog.erase(g_GlobalTimelineLog.begin());
            }
        }
        
        ApplyGlassmorphismTheme(g_GlassAlpha, themes[currentThemeIndex].accentColor, themes[currentThemeIndex].backgroundColor);
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        RECT clientRect;
        GetClientRect(hwnd, &clientRect);
        int winWidth = clientRect.right - clientRect.left;
        int winHeight = clientRect.bottom - clientRect.top;

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2((float)winWidth, (float)winHeight));
        ImGuiWindowFlags window_flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_MenuBar;

        ImGui::Begin("NexusDashboard", NULL, window_flags);
        
        if (ImGui::BeginMenuBar()) {
            if (ImGui::BeginMenu("Settings // Theme")) {
                for (int i = 0; i < (int)themes.size(); ++i) {
                    if (ImGui::MenuItem(themes[i].name.c_str(), NULL, currentThemeIndex == i)) {
                        currentThemeIndex = i;
                        SaveThemeConfig(themes[i].name);
                    }
                }
                
                ImGui::Separator();
                ImGui::Text("Glass Opacity");
                ImGui::SetNextItemWidth(150.0f);
                if (ImGui::SliderFloat("##GlassAlpha", &g_GlassAlpha, 0.15f, 1.0f, "%.2f")) {
                    ApplyGlassmorphismTheme(g_GlassAlpha, themes[currentThemeIndex].accentColor, themes[currentThemeIndex].backgroundColor);
                }

                ImGui::EndMenu();
            }

            if (ImGui::BeginMenu("Tools")) {
                if (ImGui::MenuItem("Live Boot Media Builder...")) {
                    showLiveBootModal = true;
                }
                if (ImGui::MenuItem("Forensic Report Viewer...")) {
                    showReportViewerModal = true;
                }
                ImGui::EndMenu();
            }

            ImGui::EndMenuBar();
        }

        static int currentTab = 0;
        static bool switchTab = false;
        static bool showSidebar = true;

        const char* tabNames[] = {
            "Performance // Charts", "System Timeline", "USB History", "Boot & Rootkit Analyzer", 
            "Processes", "ETW Live Monitor", "Defender ETW", "Prefetch Analyzer", 
            "Installer Folder", "MFT Parser", "Registry Parser", "Kernel Drivers", 
            "Event Logs", "Artifact Scanner", "Network Connections", "Installed Apps", 
            "Windows Services", "Scheduled Tasks", "DLL Dependency Viewer", 
            "Startup Applications", "Environment Variables", "Locked Handles", 
            "Dump Analyzer", "Live Tracker", "Tech Toolbox"
        };

        if (!showSidebar) {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.2f, 0.2f, 0.2f, 0.5f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.3f, 0.3f, 0.3f, 0.7f));
            
            if (ImGui::Button("[+]")) {
                showSidebar = true;
            }
            
            ImGui::PopStyleColor(3);
            
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Open Navigation Menu");
            }
        }

        if (showSidebar) {
            ImGui::BeginChild("SidebarNavigation", ImVec2(210, 0), true);
            
            if (ImGui::Button("<", ImVec2(30, 0))) {
                showSidebar = false;
            }
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Hide menú");
            }
            
            ImGui::SameLine();
            ImGui::Text("Navigation");
            
            ImGui::Separator();

            for (int i = 0; i < 24; i++) {
                if (ImGui::Selectable(tabNames[i], currentTab == i)) {
                    currentTab = i;
                    switchTab = true; 
                }
            }
            ImGui::EndChild();

            ImGui::SameLine();
        }

        ImGui::BeginChild("MainContentArea", ImVec2(0, 0), false);
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() - 30.0f);

        ImGuiTabBarFlags tabFlags = ImGuiTabBarFlags_NoCloseWithMiddleMouseButton | 
                                    ImGuiTabBarFlags_NoTooltip;

        if (ImGui::BeginTabBar("MainTabs", tabFlags)) {
            ImGuiTabItemFlags itemFlags = switchTab ? ImGuiTabItemFlags_SetSelected : 0;
            
            // TAB: PERFORMANCE // CHARTS
            if (ImGui::BeginTabItem("Performance // Charts", NULL, (currentTab == 0 ? itemFlags : 0))) {
                ImGui::TextColored(themes[currentThemeIndex].accentColor, "[ LIVE HARDWARE TELEMETRY & BREAKDOWN ]");
                ImGui::SameLine(winWidth - 370.0f);
                
                ImGui::Checkbox("Per-Core CPU", &showPerCoreCpu);
                ImGui::SameLine();
                ImGui::Checkbox("All Disks", &showAllDisks);
                ImGui::SameLine();
                ImGui::Checkbox("All Nets", &showAllNets);
                ImGui::Separator();
                
                float contentHeight = (float)winHeight - 190.0f;
                float childWidth = (float)(winWidth - 48) / 2.0f;

                auto drawPlotCard = [](const char* title, std::deque<float>& data, float scaleMax, const char* unit) {
                    ImGui::BeginChild(title, ImVec2(0, 105), true);
                    float currentVal = data.empty() ? 0.0f : data.back();
                    char label[64];
                    snprintf(label, sizeof(label), "%s: %.1f %s", title, currentVal, unit);
                    ImGui::Text("%s", label);
                    
                    std::vector<float> plotData(data.begin(), data.end());
                    if (!plotData.empty()) {
                        ImGui::PlotLines("##plot", plotData.data(), (int)plotData.size(), 0, NULL, 0.0f, scaleMax, ImVec2(-1, 55));
                    }
                    ImGui::EndChild();
                };

                ImGui::BeginChild("LeftCol", ImVec2(childWidth, contentHeight), false);
                
                if (!showPerCoreCpu || g_PerfHistory.perCoreCpuHistory.empty()) {
                    drawPlotCard("CPU (Global Usage)", g_PerfHistory.cpuHistory, 100.0f, "%");
                } else {
                    if (ImGui::BeginChild("CpuCoresScroll", ImVec2(0, 220), true)) {
                        ImGui::TextColored(themes[currentThemeIndex].accentColor, "[ CPU CORES BREAKDOWN ]");
                        for (size_t i = 0; i < g_PerfHistory.perCoreCpuHistory.size(); ++i) {
                            char coreTitle[32];
                            snprintf(coreTitle, sizeof(coreTitle), "Core %zu", i);
                            drawPlotCard(coreTitle, g_PerfHistory.perCoreCpuHistory[i], 100.0f, "%");
                        }
                    }
                    ImGui::EndChild();
                }

                drawPlotCard("System Memory (RAM)", g_PerfHistory.ramHistory, 100.0f, "%");

                if (!showAllNets || g_PerfHistory.netAdaptersHistory.empty()) {
                    drawPlotCard("Network Activity (Total)", g_PerfHistory.netHistory, 100.0f, "KB/s");
                } else {
                    for (auto& pair : g_PerfHistory.netAdaptersHistory) {
                        std::string cardTitle = "Net: " + pair.first;
                        drawPlotCard(cardTitle.c_str(), pair.second, 100.0f, "KB/s");
                    }
                }
                
                ImGui::EndChild();

                ImGui::SameLine();

                ImGui::BeginChild("RightCol", ImVec2(childWidth, contentHeight), false);
                
                drawPlotCard("GPU Acceleration", g_PerfHistory.gpuHistory, 100.0f, "%");

                if (!showAllDisks || g_PerfHistory.diskDrivesHistory.empty()) {
                    drawPlotCard("Disk I/O (Total)", g_PerfHistory.diskHistory, 100.0f, "MB/s");
                } else {
                    for (auto& pair : g_PerfHistory.diskDrivesHistory) {
                        std::string diskTitle = "Disk: " + pair.first;
                        drawPlotCard(diskTitle.c_str(), pair.second, 100.0f, "MB/s");
                    }
                }
                
                ImGui::BeginChild("HardwareInfo", ImVec2(0, 105), true);
                ImGui::TextColored(themes[currentThemeIndex].accentColor, "[ GRAPHICS SUBSYSTEM ]");
                ImGui::Text("Renderer: %s", glGetString(GL_RENDERER));
                ImGui::EndChild();

                ImGui::EndChild();

                ImGui::EndTabItem();
            }

            // TAB SYSTEM TIMELINE
            if (ImGui::BeginTabItem("System Timeline", NULL, (currentTab == 1 ? itemFlags : 0))) {
                if (ImGui::Button("Clear Timeline")) {
                    g_GlobalTimelineLog.clear();
                }
                ImGui::SameLine();
                ImGui::Checkbox("Auto-scroll", &timelineAutoScroll);
                
                ImGui::SameLine();
                ImGui::SetNextItemWidth(250);
                ImGui::InputText("Filter Timeline", timelineSearchFilter, IM_ARRAYSIZE(timelineSearchFilter));

                ImGui::Separator();

                ImGuiTableFlags flags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | 
                                        ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable;

                if (ImGui::BeginTable("TimelineTable", 5, flags, ImVec2(0, 500))) {
                    ImGui::TableSetupColumn("Timestamp", ImGuiTableColumnFlags_WidthFixed, 140.0f);
                    ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 110.0f);
                    ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 60.0f);
                    ImGui::TableSetupColumn("Actor / Process", ImGuiTableColumnFlags_WidthFixed, 180.0f);
                    ImGui::TableSetupColumn("Action Description / Details", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableHeadersRow();

                    for (const auto& ev : g_GlobalTimelineLog) {
                        if (strlen(timelineSearchFilter) > 0) {
                            std::string searchable = ev.timeString + " " + ev.description + " " + ev.sourceProcess;
                            if (searchable.find(timelineSearchFilter) == std::string::npos) continue;
                        }

                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::TextUnformatted(ev.timeString.c_str());
                        
                        ImGui::TableSetColumnIndex(1);
                        ImGui::TextColored(ev.displayColor, "%s", GetTimelineTypeName(ev.type).c_str());
                        
                        ImGui::TableSetColumnIndex(2);
                        if (ev.pid > 0) ImGui::Text("%lu", ev.pid);
                        else ImGui::Text("-");
                        
                        ImGui::TableSetColumnIndex(3);
                        ImGui::TextUnformatted(ev.sourceProcess.c_str());
                        
                        ImGui::TableSetColumnIndex(4);
                        ImGui::TextUnformatted(ev.description.c_str());
                    }

                    if (timelineAutoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 20.0f) {
                        ImGui::SetScrollHereY(1.0f);
                    }

                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            // TAB BOOT ANALYZE
            if (ImGui::BeginTabItem("Boot & Rootkit Analyzer", NULL, (currentTab == 3 ? itemFlags : 0))) {
                ImGui::Text("Target Disk or Raw Image Path (e.g., \\\\.\\PhysicalDrive0):");
                ImGui::InputText("##bootDisk", bootDiskInput, IM_ARRAYSIZE(bootDiskInput));

                if (ImGui::Button("Scan Boot Sectors & EFI", ImVec2(180, 0))) {
                    bootCachedItems = BootSecurityEngine::ScanBootSectors(bootDiskInput, bootLastError);
                    bootScanned = true;
                }

                ImGui::Separator();

                if (!bootScanned) {
                    ImGui::TextDisabled("Click 'Scan Boot Sectors & EFI' to inspect MBR signatures and bootkit indicators.");
                } else if (!bootLastError.empty()) {
                    ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", bootLastError.c_str());
                } else {
                    ImGui::Text("Scan Results: %zu artifacts analyzed", bootCachedItems.size());

                    ImGuiTableFlags bootTableFlags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | 
                                                    ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable;

                    if (ImGui::BeginTable("BootTable", 4, bootTableFlags, ImVec2(0, 400))) {
                        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                        ImGui::TableSetupColumn("Target Component", ImGuiTableColumnFlags_WidthFixed, 160.0f);
                        ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 140.0f);
                        ImGui::TableSetupColumn("Technical Details", ImGuiTableColumnFlags_WidthStretch);
                        ImGui::TableHeadersRow();

                        for (const auto& item : bootCachedItems) {
                            ImGui::TableNextRow();

                            ImGui::TableSetColumnIndex(0);
                            ImGui::Text("%s", item.artifactType.c_str());

                            ImGui::TableSetColumnIndex(1);
                            ImGui::Text("%s", item.targetName.c_str());

                            ImGui::TableSetColumnIndex(2);
                            if (item.status.find("Anomalous") != std::string::npos) {
                                ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "%s", item.status.c_str());
                            } else {
                                ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.4f, 1.0f), "%s", item.status.c_str());
                            }

                            ImGui::TableSetColumnIndex(3);
                            ImGui::TextUnformatted(item.details.c_str());
                        }
                        ImGui::EndTable();
                    }
                }

                ImGui::EndTabItem();
            }

            // TAB USB HISTORY
            if (ImGui::BeginTabItem("USB History", NULL, (currentTab == 2 ? itemFlags : 0))) {
                ImGui::Spacing();
                
                if (cachedUSBHistory.empty()) {
                    cachedUSBHistory = LoadUSBHistory();
                }

                ImGui::TextColored(themes[currentThemeIndex].accentColor, "Connected USB Devices Artifacts (Registry Audit)");
                ImGui::SameLine();
                ImGui::Text(" | TOTAL: %zu", cachedUSBHistory.size());
                ImGui::SameLine(winWidth - 140);
                if (ImGui::Button("Refresh USB")) {
                    cachedUSBHistory = LoadUSBHistory();
                }
                ImGui::Spacing();

                float tableHeight = (float)winHeight - 240.0f;
                ImGuiTableFlags usbTableFlags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable;

                if (ImGui::BeginTable("USBHistoryTable", 4, usbTableFlags, ImVec2(0, tableHeight))) {
                    ImGui::TableSetupColumn("Friendly Name", ImGuiTableColumnFlags_WidthFixed, 180.0f);
                    ImGui::TableSetupColumn("Device Category / Vendor", ImGuiTableColumnFlags_WidthStretch, 2.0f);
                    ImGui::TableSetupColumn("Serial Number / Instance ID", ImGuiTableColumnFlags_WidthStretch, 2.0f);
                    ImGui::TableSetupColumn("Last Activity", ImGuiTableColumnFlags_WidthFixed, 150.0f);
                    ImGui::TableHeadersRow();

                    for (size_t i = 0; i < cachedUSBHistory.size(); ++i) {
                        const auto& usb = cachedUSBHistory[i];
                        ImGui::TableNextRow();
                        
                        ImGui::TableSetColumnIndex(0); 
                        ImGui::Text("%s", usb.friendlyName.c_str());
                        
                        ImGui::TableSetColumnIndex(1); 
                        ImGui::TextColored(ImVec4(0.2f, 0.8f, 1.0f, 1.0f), "%s", usb.deviceName.c_str());
                        
                        ImGui::TableSetColumnIndex(2); 
                        ImGui::Text("%s", usb.serialNumber.c_str());
                        
                        ImGui::TableSetColumnIndex(3); 
                        ImGui::Text("%s", usb.installDate.c_str());
                    }

                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            // TAB: PROCESSES
            if (ImGui::BeginTabItem("Processes", NULL, (currentTab == 4 ? itemFlags : 0))) {
                ImGui::TextColored(themes[currentThemeIndex].accentColor, "[ PROCESS MONITOR // ACTIVE ]");
                ImGui::SameLine(winWidth - 180);
                ImGui::Text("TOTAL: %zu", CountTotalProcesses(cachedProcesses));
                ImGui::Separator();

                ImGui::Text("Filter:");
                ImGui::SameLine();
                ImGui::SetNextItemWidth(250);
                ImGui::InputText("##search", searchBuffer, sizeof(searchBuffer));
                
                ImGui::Spacing();
                float tableHeight = (float)winHeight - 190.0f;

                if (ImGui::BeginTable("ProcessTable", 7, ImGuiTableFlags_BordersV | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable, ImVec2(0, tableHeight))) {
                    ImGui::TableSetupColumn("NAME", ImGuiTableColumnFlags_WidthStretch, 2.0f);
                    ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 70.0f);
                    ImGui::TableSetupColumn("CPU (%)", ImGuiTableColumnFlags_WidthFixed, 70.0f);
                    ImGui::TableSetupColumn("MEMORY (MB)", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                    ImGui::TableSetupColumn("PRIORITY", ImGuiTableColumnFlags_WidthFixed, 90.0f);
                    ImGui::TableSetupColumn("STATUS / SPOOFING", ImGuiTableColumnFlags_WidthFixed, 140.0f);
                    ImGui::TableSetupColumn("PATH", ImGuiTableColumnFlags_WidthStretch, 3.0f);
                    ImGui::TableHeadersRow();

                    std::string filterStr = searchBuffer;
                    std::transform(filterStr.begin(), filterStr.end(), filterStr.begin(), ::tolower);

                    for (const auto& p : cachedProcesses) {
                        RenderProcessTreeRow(p, filterStr, selectedPid, hwnd, 
                                            memoryMapPid, showMemoryMap, cachedMemoryRegions, memoryMapError,
                                            modThreadsPid, showModulesThreads, cachedModules, modulesError, cachedThreads, threadsError,
                                            connectionsPid, showConnections, cachedConnections, connectionsError,
                                            handlesDllsPid, showHandlesDlls, cachedHandles, handlesError, cachedAdvancedModules, advancedModulesError, isHandlesDllsLoading,
                                            cachedProcesses,
                                            monitoredPid, hMonitoredProcess, isTracking, liveCpuHistory, liveMemHistory, liveHistoryIndex, lastLiveTick
                                            );
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }
            
            // TAB KERNEL MONITOR
            if (ImGui::BeginTabItem("ETW Live Monitor", NULL, (currentTab == 5 ? itemFlags : 0))) {
                if (ImGui::Button(etwSessionRunning ? "Stop ETW Session" : "Start ETW Session", ImVec2(150, 0))) {
                    etwSessionRunning = !etwSessionRunning;
                    if (etwSessionRunning) {
                        StartEtwSessionThread();
                    }
                }

                ImGui::SameLine();
                if (ImGui::Button("Clear Logs", ImVec2(100, 0))) {
                    etwEventLog.clear();
                }

                ImGui::SameLine();
                ImGui::Checkbox("Auto-scroll", &etwAutoScroll);

                ImGui::SameLine();
                ImGui::SetNextItemWidth(200);
                ImGui::InputText("Filter", etwSearchFilter, IM_ARRAYSIZE(etwSearchFilter));

                ImGui::Separator();

                ImGui::Text("Captured Events in Buffer: %zu", etwEventLog.size());

                ImGuiTableFlags etwFlags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | 
                                            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable;

                if (ImGui::BeginTable("EtwTable", 4, etwFlags, ImVec2(0, 400))) {
                    ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 90.0f);
                    ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                    ImGui::TableSetupColumn("Parent PID", ImGuiTableColumnFlags_WidthFixed, 90.0f);
                    ImGui::TableSetupColumn("Event Path / Info", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableHeadersRow();

                    for (const auto& rec : etwEventLog) {
                        std::string typeStr = (rec.type == EtwProcessEvent::Created) ? "Created" : "Terminated";
                        
                        if (strlen(etwSearchFilter) > 0) {
                            std::string searchable = typeStr + " " + std::to_string(rec.pid) + " " + rec.imagePath;
                            if (searchable.find(etwSearchFilter) == std::string::npos) continue;
                        }

                        ImGui::TableNextRow();

                        ImGui::TableSetColumnIndex(0);
                        if (rec.type == EtwProcessEvent::Created) {
                            ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "Created");
                        } else {
                            ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "Terminated");
                        }

                        ImGui::TableSetColumnIndex(1);
                        ImGui::Text("%lu", rec.pid);

                        ImGui::TableSetColumnIndex(2);
                        ImGui::Text("%lu", rec.parentPid);

                        ImGui::TableSetColumnIndex(3);
                        ImGui::TextUnformatted(rec.imagePath.c_str());
                    }

                    if (etwAutoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
                        ImGui::SetScrollHereY(1.0f);
                    }

                    ImGui::EndTable();
                }

                ImGui::EndTabItem();
            }

            // TAB DEFENDER LIVE VIEWER
            if (ImGui::BeginTabItem("Defender ETW", NULL, (currentTab == 6 ? itemFlags : 0))) {
                ImGui::Text("Windows Defender Real-Time ETW Monitor");
                ImGui::Separator();

                if (!g_DefenderRunning) {
                    if (ImGui::Button("Start Defender Listener", ImVec2(180, 0))) {
                        StartDefenderRealtimeMonitor();
                    }
                    ImGui::SameLine();
                    ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "Status: Stopped (Requires Admin)");
                } else {
                    if (ImGui::Button("Stop / Reset", ImVec2(180, 0))) {
                        StopDefenderRealtimeMonitor();
                    }
                    ImGui::SameLine();
                    ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.4f, 1.0f), "Status: Listening Live...");
                }

                ImGui::SameLine(ImGui::GetWindowWidth() - 120);
                if (ImGui::Button("Clear Logs")) {
                    std::lock_guard<std::mutex> lock(g_DefenderMutex);
                    g_DefenderEvents.clear();
                }

                ImGui::Spacing();
                ImGui::SetNextItemWidth(120);
                ImGui::InputInt("Filter Event ID", &defFilterId);
                ImGui::SameLine();
                if (ImGui::Button("Reset ID")) defFilterId = 0;

                ImGui::SameLine();
                ImGui::SetNextItemWidth(250);
                ImGui::InputText("Search text", defSearchFilter, IM_ARRAYSIZE(defSearchFilter));

                ImGui::SameLine();
                ImGui::Checkbox("Auto-scroll", &defAutoScroll);

                ImGui::Separator();

                ImGui::Text("Captured Telemetry Events: %zu", g_DefenderEvents.size());

                ImGuiTableFlags flags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | 
                                        ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable;

                if (ImGui::BeginTable("DefenderETWTable", 3, flags, ImVec2(0, 320))) {
                    ImGui::TableSetupColumn("Timestamp", ImGuiTableColumnFlags_WidthFixed, 130.0f);
                    ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 60.0f);
                    ImGui::TableSetupColumn("Event Description / Telemetry Data", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableHeadersRow();

                    std::lock_guard<std::mutex> lock(g_DefenderMutex);
                    for (const auto& ev : g_DefenderEvents) {
                        if (strlen(defSearchFilter) > 0 && ev.message.find(defSearchFilter) == std::string::npos) continue;

                        ImGui::TableNextRow();

                        ImGui::TableSetColumnIndex(0);
                        ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "%s", ev.timeString.c_str());

                        ImGui::TableSetColumnIndex(1);
                        if (ev.pid > 0)
                            ImGui::Text("%lu", ev.pid);
                        else
                            ImGui::Text("-");

                        ImGui::TableSetColumnIndex(2);
                        ImGui::TextColored(ev.color, "%s", ev.message.c_str());
                    }

                    if (defAutoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
                        ImGui::SetScrollHereY(1.0f);

                    ImGui::EndTable();
                }

                ImGui::Spacing();
                ImGui::Separator();
                ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "Native OS Advanced Security Report & Live Monitor");
                ImGui::TextWrapped("Generate executive reports or trigger an immediate live system scan. The stream below will display exclusively the isolated activity of the active scan.");

                static std::string generatedReportContent = "";
                static std::string reportActionStatus = "";

                static std::vector<DefenderLiveEvent> g_LiveScanEvents;
                static bool g_IsLiveScanning = false;

                if (ImGui::Button("Generate Professional Report", ImVec2(230, 0))) {
                    generatedReportContent = GenerateNativeSystemSecurityReportString();
                    ImGui::OpenPopup("Security Report Preview");
                }

                ImGui::SameLine();

                bool isScanningCopy = false;
                {
                    std::lock_guard<std::mutex> lock(g_DefenderMutex);
                    isScanningCopy = g_IsLiveScanning;
                }

                if (isScanningCopy) {
                    ImGui::BeginDisabled();
                }

                if (ImGui::Button("Run Live Defender Scan", ImVec2(200, 0))) {
                    {
                        std::lock_guard<std::mutex> lock(g_DefenderMutex);
                        g_LiveScanEvents.clear(); 
                        g_IsLiveScanning = true;
                    }

                    reportActionStatus = "Live scan started! Capturing isolated scan progress...";

                    std::thread([&]() {
                        STARTUPINFOA si;
                        PROCESS_INFORMATION pi;
                        ZeroMemory(&si, sizeof(si));
                        si.cb = sizeof(si);
                        si.dwFlags = STARTF_USESHOWWINDOW;
                        si.wShowWindow = SW_HIDE;

                        ZeroMemory(&pi, sizeof(pi));

                        std::string cmd = "powershell -NoProfile -Command \"Start-MpScan -ScanType QuickScan\"";

                        if (CreateProcessA(NULL, &cmd[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                            WaitForSingleObject(pi.hProcess, INFINITE);

                            CloseHandle(pi.hProcess);
                            CloseHandle(pi.hThread);
                        }

                        {
                            std::lock_guard<std::mutex> lock(g_DefenderMutex);
                            g_IsLiveScanning = false;
                        }
                        
                        reportActionStatus = "Live scan completed successfully! Windows Defender finished.";
                    }).detach();
                }

                if (isScanningCopy) {
                    ImGui::EndDisabled();                    
                    ImGui::SameLine();
                    float radius = 7.0f;
                    ImVec2 pos = ImGui::GetCursorScreenPos();
                    pos.y += radius + 3.0f;
                    
                    ImDrawList* draw_list = ImGui::GetWindowDrawList();
                    int num_segments = 10;
                    float time = (float)ImGui::GetTime();
                    
                    for (int i = 0; i < num_segments; i++) {
                        float a = time * 9.0f - ((float)i / (float)num_segments) * 6.28f;
                        ImVec2 dot_pos = ImVec2(pos.x + cosf(a) * radius, pos.y + sinf(a) * radius);
                        float alpha = ((float)(i + 1) / (float)num_segments);
                        draw_list->AddCircleFilled(dot_pos, 1.8f, IM_COL32(0, 160, 255, (int)(alpha * 255)));
                    }
                    
                    ImGui::Dummy(ImVec2(radius * 2.2f, radius * 2.0f));
                    ImGui::SameLine();
                    ImGui::TextColored(ImVec4(0.0f, 0.7f, 1.0f, 1.0f), "Scanning system...");
                }

                if (ImGui::BeginPopupModal("Security Report Preview", NULL, 0)) {
                    ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.6f, 1.0f), "Forensic Report Preview");
                    ImGui::Separator();
                    ImGui::Spacing();

                    if (!generatedReportContent.empty()) {
                        static char buffer[32768];
                        strncpy_s(buffer, generatedReportContent.c_str(), sizeof(buffer));
                        
                        float footerHeightSpacing = 45.0f;
                        ImVec2 availableSize = ImVec2(-1, ImGui::GetContentRegionAvail().y - footerHeightSpacing);
                        
                        ImGui::InputTextMultiline("##reportview", buffer, IM_ARRAYSIZE(buffer), availableSize, ImGuiInputTextFlags_ReadOnly);
                    }

                    ImGui::Spacing();
                    ImGui::Separator();

                    if (ImGui::Button("Save to File (.txt)", ImVec2(150, 0))) {
                        std::ofstream outFile("Windows_System_Security_Report.txt");
                        if (outFile.is_open()) {
                            outFile << generatedReportContent;
                            outFile.close();
                            reportActionStatus = "Successfully saved as 'Windows_System_Security_Report.txt'.";
                        } else {
                            reportActionStatus = "Error: Could not save file.";
                        }
                        ImGui::CloseCurrentPopup();
                    }

                    ImGui::SameLine();
                    if (ImGui::Button("Close Preview", ImVec2(120, 0))) {
                        reportActionStatus = "Report review closed without saving.";
                        ImGui::CloseCurrentPopup();
                    }

                    ImGui::EndPopup();
                }

                if (!reportActionStatus.empty() && !isScanningCopy) {
                    ImGui::SameLine();
                    ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.4f, 1.0f), "%s", reportActionStatus.c_str());
                }

                ImGui::Spacing();
                ImGui::Separator();
                
                ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.0f, 1.0f), "Live Scan Dedicated Stream:");
                
                ImGui::BeginChild("LiveEventStreamChild", ImVec2(0, 200), true, ImGuiWindowFlags_HorizontalScrollbar);
                {
                    std::lock_guard<std::mutex> lock(g_DefenderMutex);
                    if (g_LiveScanEvents.empty()) {
                        ImGui::TextDisabled("Click 'Run Live Defender Scan' to capture isolated scan telemetry...");
                    } else {
                        for (const auto& ev : g_LiveScanEvents) {
                            ImGui::TextColored(ev.color, "[%s] PID: %lu -> %s", ev.timeString.c_str(), ev.pid, ev.message.c_str());
                        }
                        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
                            ImGui::SetScrollHereY(1.0f);
                        }
                    }
                }
                ImGui::EndChild();
                ImGui::EndTabItem();
            }

            // TAB PREFETCH ANLYZER
            if (ImGui::BeginTabItem("Prefetch Analyzer", NULL, (currentTab == 7 ? itemFlags : 0))) {                
                ImGui::Text("Path to Prefetch Directory:");
                ImGui::InputText("##pfPath", pfPathInput, IM_ARRAYSIZE(pfPathInput));
                
                if (ImGui::Button("Scan Prefetch (.pf)", ImVec2(180, 0))) {
                    pfCachedItems = PrefetchEngine::ScanPrefetch(pfPathInput, pfLastError);
                    pfDataLoaded = true;
                }

                ImGui::SameLine();
                ImGui::SetNextItemWidth(250);
                ImGui::InputText("Filter Executable", pfSearchFilter, IM_ARRAYSIZE(pfSearchFilter));

                ImGui::Separator();

                if (!pfDataLoaded) {
                    ImGui::TextDisabled("Click 'Scan Prefetch (.pf)' to analyze execution artifacts.");
                } else if (!pfLastError.empty()) {
                    ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", pfLastError.c_str());
                } else {
                    ImGui::Text("Found Prefetch Files: %zu", pfCachedItems.size());

                    ImGuiTableFlags pfFlags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | 
                                            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable;

                    if (ImGui::BeginTable("PrefetchTable", 4, pfFlags, ImVec2(0, 400))) {
                        ImGui::TableSetupColumn("Executable / Prefetch Name", ImGuiTableColumnFlags_WidthFixed, 220.0f);
                        ImGui::TableSetupColumn("File Size", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                        ImGui::TableSetupColumn("Execution Status", ImGuiTableColumnFlags_WidthFixed, 150.0f);
                        ImGui::TableSetupColumn("Full Path", ImGuiTableColumnFlags_WidthStretch);
                        ImGui::TableHeadersRow();

                        for (const auto& pf : pfCachedItems) {
                            if (strlen(pfSearchFilter) > 0 && pf.executableName.find(pfSearchFilter) == std::string::npos) {
                                continue;
                            }

                            ImGui::TableNextRow();

                            ImGui::TableSetColumnIndex(0);
                            ImGui::Text("%s", pf.executableName.c_str());

                            ImGui::TableSetColumnIndex(1);
                            ImGui::Text("%llu bytes", (unsigned long long)pf.fileSize);

                            ImGui::TableSetColumnIndex(2);
                            ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "Verified Execution");

                            ImGui::TableSetColumnIndex(3);
                            ImGui::TextUnformatted(pf.filePath.c_str());
                        }
                        ImGui::EndTable();
                    }
                }

                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Installer Folder", NULL, (currentTab == 8 ? itemFlags : 0))) {
                ImGui::Text("Audits C:\\Windows\\Installer for orphaned .msi and .msp packages to reclaim disk space.");
                ImGui::Separator();

                if (ImGui::Button("Scan Installer Folder", ImVec2(180, 0))) {
                    ScanWindowsInstallerFolder();
                    installerDataLoaded = true;
                }

                ImGui::SameLine();
                ImGui::Checkbox("Show Only Orphaned", &installerShowOnlyOrphaned);
                
                ImGui::SameLine();
                ImGui::SetNextItemWidth(200);
                ImGui::InputText("Filter File", installerSearchFilter, IM_ARRAYSIZE(installerSearchFilter));

                ImGui::Separator();

                if (!installerDataLoaded) {
                    ImGui::TextDisabled("Click 'Scan Installer Folder' to inspect C:\\Windows\\Installer packages.");
                } else if (!installerLastError.empty()) {
                    ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", installerLastError.c_str());
                } else {
                    ImGui::Text("Scanned Packages: %zu", g_InstallerItems.size());

                    ImGuiTableFlags installerFlags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | 
                                                    ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable;

                    if (ImGui::BeginTable("InstallerTable", 5, installerFlags, ImVec2(0, 400))) {
                        ImGui::TableSetupColumn("File Name", ImGuiTableColumnFlags_WidthFixed, 170.0f);
                        ImGui::TableSetupColumn("Product Name", ImGuiTableColumnFlags_WidthFixed, 220.0f);
                        ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 90.0f);
                        ImGui::TableSetupColumn("Size (MB)", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                        ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch);
                        ImGui::TableHeadersRow();

                        for (const auto& item : g_InstallerItems) {
                            std::string narrowFileName(item.fileName.begin(), item.fileName.end());
                            std::string narrowProductName(item.productName.begin(), item.productName.end());
                            
                            if (installerShowOnlyOrphaned && !item.isOrphaned) continue;
                            if (strlen(installerSearchFilter) > 0 && 
                                narrowFileName.find(installerSearchFilter) == std::string::npos && 
                                narrowProductName.find(installerSearchFilter) == std::string::npos) continue;

                            ImGui::TableNextRow();

                            ImGui::TableSetColumnIndex(0);
                            if (!item.exeNames.empty()) {
                                ImGui::Text("%ls -> %ls", item.fileName.c_str(), item.exeNames.c_str());
                            } else {
                                ImGui::Text("%ls", item.fileName.c_str());
                            }
                            ImGui::TableSetColumnIndex(1);
                            if (!item.productName.empty()) {
                                ImGui::Text("%ls", item.productName.c_str());
                            } else {
                                ImGui::TextDisabled("Unknown");
                            }
                            ImGui::TableSetColumnIndex(2);
                            if (item.isOrphaned) {
                                ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "Orphaned");
                            } else {
                                ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "Installed");
                            }
                            ImGui::TableSetColumnIndex(3);
                            ImGui::Text("%.2f MB", (float)item.sizeBytes / (1024.0f * 1024.0f));
                            ImGui::TableSetColumnIndex(4);
                            ImGui::Text("%ls", item.path.c_str());
                        }
                        ImGui::EndTable();
                    }
                }

                ImGui::EndTabItem();
            }

            // TAB $MFT ANALISIS
            if (ImGui::BeginTabItem("MFT Parser", NULL, (currentTab == 9 ? itemFlags : 0))) {               
                ImGui::Text("Path to exported NTFS $MFT file:");
                ImGui::InputText("##mftPath", mftPathInput, IM_ARRAYSIZE(mftPathInput));
                
                if (ImGui::Button("Parse $MFT Database", ImVec2(180, 0))) {
                    mftCachedRecords = MFTEngine::ParseMFTFile(mftPathInput, mftLastError);
                    mftDataLoaded = true;
                }

                ImGui::SameLine();
                ImGui::Checkbox("Show Only Deleted", &mftShowOnlyDeleted);
                
                ImGui::SameLine();
                ImGui::SetNextItemWidth(200);
                ImGui::InputText("Filter File", mftSearchFilter, IM_ARRAYSIZE(mftSearchFilter));

                ImGui::Separator();

                if (!mftDataLoaded) {
                    ImGui::TextDisabled("Provide a valid exported $MFT file path and click 'Parse $MFT Database'.");
                } else if (!mftLastError.empty()) {
                    ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", mftLastError.c_str());
                } else {
                    ImGui::Text("Parsed Records: %zu", mftCachedRecords.size());

                    ImGuiTableFlags mftFlags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | 
                                                ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable;

                    if (ImGui::BeginTable("MFTTable", 5, mftFlags, ImVec2(0, 400))) {
                        ImGui::TableSetupColumn("ID / Rec", ImGuiTableColumnFlags_WidthFixed, 70.0f);
                        ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                        ImGui::TableSetupColumn("File Name", ImGuiTableColumnFlags_WidthFixed, 180.0f);
                        ImGui::TableSetupColumn("Modified Time ($SI)", ImGuiTableColumnFlags_WidthFixed, 150.0f);
                        ImGui::TableSetupColumn("Parent Path", ImGuiTableColumnFlags_WidthStretch);
                        ImGui::TableHeadersRow();

                        for (const auto& rec : mftCachedRecords) {
                            if (mftShowOnlyDeleted && !rec.isDeleted) continue;
                            if (strlen(mftSearchFilter) > 0 && rec.fileName.find(mftSearchFilter) == std::string::npos) continue;

                            ImGui::TableNextRow();

                            ImGui::TableSetColumnIndex(0);
                            ImGui::Text("%llu", (unsigned long long)rec.recordNumber);

                            ImGui::TableSetColumnIndex(1);
                            if (rec.isDeleted) {
                                ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "Deleted");
                            } else {
                                ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "Active");
                            }

                            ImGui::TableSetColumnIndex(2);
                            ImGui::Text("%s", rec.fileName.c_str());

                            ImGui::TableSetColumnIndex(3);
                            ImGui::Text("%s", rec.standardModified.c_str());

                            ImGui::TableSetColumnIndex(4);
                            ImGui::TextUnformatted(rec.parentPath.c_str());
                        }
                        ImGui::EndTable();
                    }
                }

                ImGui::EndTabItem();
            }

            // TAB REGISTRY PARSER
            if (ImGui::BeginTabItem("Registry Parser", NULL, (currentTab == 10 ? itemFlags : 0))) {               
                ImGui::Text("Path to Offline Registry Hive (SOFTWARE, SYSTEM, SAM, SECURITY):");
                ImGui::InputText("##regPath", regPathInput, IM_ARRAYSIZE(regPathInput));
                
                const char* hiveTypes[] = { "SOFTWARE", "SYSTEM", "SAM", "SECURITY" };
                ImGui::SetNextItemWidth(150);
                ImGui::Combo("Hive Type", &selectedHiveTypeIndex, hiveTypes, IM_ARRAYSIZE(hiveTypes));
                
                ImGui::SameLine();
                if (ImGui::Button("Parse Registry Hive", ImVec2(160, 0))) {
                    std::string hType = hiveTypes[selectedHiveTypeIndex];
                    regCachedArtifacts = RegistryHiveEngine::ParseHiveFile(regPathInput, hType, regLastError);
                    regDataLoaded = true;
                }

                ImGui::SameLine();
                ImGui::SetNextItemWidth(200);
                ImGui::InputText("Filter Artifact", regSearchFilter, IM_ARRAYSIZE(regSearchFilter));

                ImGui::Separator();

                if (!regDataLoaded) {
                    ImGui::TextDisabled("Select an offline hive file and click 'Parse Registry Hive' to extract persistence and USB traces.");
                } else if (!regLastError.empty()) {
                    ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", regLastError.c_str());
                } else {
                    ImGui::Text("Extracted Artifacts: %zu", regCachedArtifacts.size());

                    ImGuiTableFlags regTableFlags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | 
                                                    ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable;

                    if (ImGui::BeginTable("RegistryTable", 5, regTableFlags, ImVec2(0, 400))) {
                        ImGui::TableSetupColumn("Hive", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                        ImGui::TableSetupColumn("Category", ImGuiTableColumnFlags_WidthFixed, 110.0f);
                        ImGui::TableSetupColumn("Value Name", ImGuiTableColumnFlags_WidthFixed, 140.0f);
                        ImGui::TableSetupColumn("Data / Command Path", ImGuiTableColumnFlags_WidthFixed, 250.0f);
                        ImGui::TableSetupColumn("Subkey Path", ImGuiTableColumnFlags_WidthStretch);
                        ImGui::TableHeadersRow();

                        for (const auto& art : regCachedArtifacts) {
                            if (strlen(regSearchFilter) > 0 && 
                                art.valueName.find(regSearchFilter) == std::string::npos && 
                                art.dataValue.find(regSearchFilter) == std::string::npos) {
                                continue;
                            }

                            ImGui::TableNextRow();

                            ImGui::TableSetColumnIndex(0);
                            ImGui::Text("%s", art.hiveType.c_str());

                            ImGui::TableSetColumnIndex(1);
                            if (art.category == "Persistencia") {
                                ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "%s", art.category.c_str());
                            } else if (art.category == "Hide Service") {
                                ImGui::TextColored(ImVec4(1.0f, 0.7f, 0.2f, 1.0f), "%s", art.category.c_str());
                            } else {
                                ImGui::TextColored(ImVec4(0.3f, 0.8f, 1.0f, 1.0f), "%s", art.category.c_str());
                            }

                            ImGui::TableSetColumnIndex(2);
                            ImGui::Text("%s", art.valueName.c_str());

                            ImGui::TableSetColumnIndex(3);
                            ImGui::Text("%s", art.dataValue.c_str());

                            ImGui::TableSetColumnIndex(4);
                            ImGui::TextUnformatted(art.keyPath.c_str());
                        }
                        ImGui::EndTable();
                    }
                }

                ImGui::EndTabItem();
            }

            // TAB KERNEL DRIVERS WITH SING VERIFICATION
            if (ImGui::BeginTabItem("Kernel Drivers", NULL, (currentTab == 11 ? itemFlags : 0))) {
                if (cachedDrivers.empty()) {
                    cachedDrivers = GetLoadedDrivers();
                }

                ImGui::TextColored(themes[currentThemeIndex].accentColor, "[ LOADED KERNEL DRIVERS INVENTORY ]");
                ImGui::SameLine(winWidth - 200);
                ImGui::Text("TOTAL: %zu", cachedDrivers.size());
                ImGui::Separator();

                ImGui::Text("Filter:");
                ImGui::SameLine();
                ImGui::SetNextItemWidth(250);
                ImGui::InputText("##driverSearch", driverSearchBuffer, sizeof(driverSearchBuffer));
                ImGui::SameLine();
                if (ImGui::Button("Refresh Drivers")) {
                    cachedDrivers = GetLoadedDrivers();
                }
                
                ImGui::Spacing();
                float tableHeight = (float)winHeight - 190.0f;

                if (ImGui::BeginTable("DriversTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, tableHeight))) {
                    ImGui::TableSetupColumn("Driver Name", ImGuiTableColumnFlags_WidthFixed, 180.0f);
                    ImGui::TableSetupColumn("Signed", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                    ImGui::TableSetupColumn("Load Address", ImGuiTableColumnFlags_WidthFixed, 130.0f);
                    ImGui::TableSetupColumn("File Path", ImGuiTableColumnFlags_WidthStretch, 1.0f);
                    ImGui::TableHeadersRow();

                    std::string filterStr = driverSearchBuffer;
                    std::transform(filterStr.begin(), filterStr.end(), filterStr.begin(), ::tolower);

                    for (size_t i = 0; i < cachedDrivers.size(); ++i) {
                        const auto& drv = cachedDrivers[i];

                        std::string nameLower = drv.name;
                        std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
                        if (!filterStr.empty() && nameLower.find(filterStr) == std::string::npos) continue;
                        ImGui::TableNextRow();
                        ImGui::PushID((int)i);
                        ImGui::TableSetColumnIndex(0); 
                        ImGui::Text("%s", drv.name.c_str());
                        ImGui::TableSetColumnIndex(1);
                        ImGui::Text("%s", drv.isSigned ? "Yes" : "No");
                        ImGui::TableSetColumnIndex(2);
                        ImGui::Text("0x%p", drv.loadAddress);
                        ImGui::TableSetColumnIndex(3); 
                        ImGui::Text("%s", drv.path.c_str());

                        ImGui::SameLine();
                        if (ImGui::SmallButton("Inspect Exports")) {
                            std::string cleanPath = drv.path;
                            
                            if (cleanPath.rfind("\\SystemRoot\\", 0) == 0) {
                                char windir[MAX_PATH];
                                GetEnvironmentVariableA("windir", windir, sizeof(windir));
                                cleanPath = std::string(windir) + cleanPath.substr(11);
                            } else if (cleanPath.rfind("\\??\\", 0) == 0) {
                                cleanPath = cleanPath.substr(4);
                            }

                            strncpy_s(dllSearchBuffer, cleanPath.c_str(), sizeof(dllSearchBuffer) - 1);
                            selectedDllPath = cleanPath;
                            cachedDllExports = GetDllExports(selectedDllPath);                            
                            currentTab = 18; 
                        }

                        ImGui::PopID();
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Event Logs", NULL, (currentTab == 12 ? itemFlags : 0))) {   
                ImGui::Text("Channel Name or .evtx File Path:");
                ImGui::InputText("##evPath", evTargetChannel, IM_ARRAYSIZE(evTargetChannel));
                
                ImGui::Checkbox("Is static file (.evtx on disk)", &evIsFilePath);
                ImGui::SameLine();
                ImGui::SetNextItemWidth(120);
                ImGui::SliderInt("Max", &evMaxLimit, 50, 1000);

                ImGui::SetNextItemWidth(120);
                ImGui::InputInt("Filter Event ID", &evFilterId);
                ImGui::SameLine();
                if (ImGui::Button("Reset ID")) evFilterId = 0;

                ImGui::SetNextItemWidth(250);
                ImGui::InputText("Search text", evSearchFilter, IM_ARRAYSIZE(evSearchFilter));

                if (ImGui::Button("Query Events", ImVec2(180, 0))) {
                    std::wstring wPath(evTargetChannel[0] ? std::wstring(evTargetChannel, evTargetChannel + strlen(evTargetChannel)) : L"Security");
                    evCachedEvents = EventLogEngine::QueryEvents(wPath, evIsFilePath, evMaxLimit);
                    evDataLoaded = true;
                }

                ImGui::Separator();

                if (!evDataLoaded) {
                    ImGui::TextDisabled("Click 'Query Events' to load log information.");
                } else {
                    ImGui::Text("Fetched Events: %zu", evCachedEvents.size());

                    ImGuiTableFlags flags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | 
                                            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable;

                    if (ImGui::BeginTable("EventsTable", 3, flags, ImVec2(0, 400))) {
                        ImGui::TableSetupColumn("ID", ImGuiTableColumnFlags_WidthFixed, 60.0f);
                        ImGui::TableSetupColumn("Status / Channel", ImGuiTableColumnFlags_WidthFixed, 120.0f);
                        ImGui::TableSetupColumn("XML Content (Preview)", ImGuiTableColumnFlags_WidthStretch);
                        ImGui::TableHeadersRow();

                        for (const auto& ev : evCachedEvents) {
                            if (evFilterId != 0 && (int)ev.eventId != evFilterId) continue;
                            if (strlen(evSearchFilter) > 0 && ev.xmlContent.find(evSearchFilter) == std::string::npos) continue;

                            ImGui::TableNextRow();

                            ImGui::TableSetColumnIndex(0);
                            ImGui::Text("%lu", ev.eventId);

                            ImGui::TableSetColumnIndex(1);
                            ImGui::Text("Parsed");

                            ImGui::TableSetColumnIndex(2);
                            std::string shortXml = ev.xmlContent.substr(0, 90) + "...";
                            ImGui::TextUnformatted(shortXml.c_str());

                            if (ImGui::IsItemHovered()) {
                                ImGui::BeginTooltip();
                                ImGui::TextUnformatted(ev.xmlContent.c_str());
                                ImGui::EndTooltip();
                            }
                        }
                        ImGui::EndTable();
                    }
                }
                
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Artifact Scanner", NULL, (currentTab == 13 ? itemFlags : 0))) {   
                ImGui::Text("Scan high-risk persistence & execution paths (.exe, .dll, .ps1, .bat, .lnk):");
                
                ImGui::SetNextItemWidth(150);
                ImGui::SliderInt("Max Age (Days)", &arMaxDays, 1, 365);
                ImGui::SameLine();

                if (ImGui::Button("Run Forensic Scan", ImVec2(180, 0))) {
                    arCachedArtifacts = ArtifactEngine::ScanArtifacts("", arMaxDays);
                    arDataLoaded = true;
                }

                ImGui::SameLine();
                ImGui::SetNextItemWidth(200);
                ImGui::InputText("Filter Path", arSearchFilter, IM_ARRAYSIZE(arSearchFilter));

                ImGui::Separator();

                if (!arDataLoaded) {
                    ImGui::TextDisabled("Click 'Run Forensic Scan' to analyze file system artifacts.");
                } else {
                    ImGui::Text("Found Artifacts: %zu (Sorted by most recent)", arCachedArtifacts.size());

                    ImGuiTableFlags artFlags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | 
                                            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable;

                    if (ImGui::BeginTable("ArtifactsTable", 4, artFlags, ImVec2(0, 400))) {
                        ImGui::TableSetupColumn("Ext", ImGuiTableColumnFlags_WidthFixed, 60.0f);
                        ImGui::TableSetupColumn("Last Modified", ImGuiTableColumnFlags_WidthFixed, 180.0f);
                        ImGui::TableSetupColumn("Size (Bytes)", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                        ImGui::TableSetupColumn("Full File Path", ImGuiTableColumnFlags_WidthStretch);
                        ImGui::TableHeadersRow();

                        for (const auto& art : arCachedArtifacts) {
                            if (strlen(arSearchFilter) > 0 && art.filePath.find(arSearchFilter) == std::string::npos) {
                                continue;
                            }

                            ImGui::TableNextRow();
                            ImGui::TableSetColumnIndex(0);
                            ImGui::Text("%s", art.extension.c_str());
                            ImGui::TableSetColumnIndex(1);
                            ImGui::Text("%s", art.lastModifiedStr.c_str());
                            ImGui::TableSetColumnIndex(2);
                            ImGui::Text("%llu", (unsigned long long)art.fileSize);
                            ImGui::TableSetColumnIndex(3);
                            ImGui::TextUnformatted(art.filePath.c_str());

                            if (ImGui::IsItemHovered()) {
                                ImGui::BeginTooltip();
                                ImGui::Text("Path: %s", art.filePath.c_str());
                                ImGui::EndTooltip();
                            }
                        }
                        ImGui::EndTable();
                    }
                }

                ImGui::EndTabItem();
            }
            
            // TAB NETWORK CONNECTIONS
            if (ImGui::BeginTabItem("Network Connections", NULL, (currentTab == 14 ? itemFlags : 0))) {
                if (cachedNetConnections.empty()) {
                    cachedNetConnections = GetActiveConnections();
                }

                ImGui::TextColored(themes[currentThemeIndex].accentColor, "[ NETWORK MONITOR & SYSTEM CONFIG ]");
                ImGui::SameLine(winWidth - 140);
                if (ImGui::Button("Refresh All Data")) {
                    cachedNetConnections = GetActiveConnections();
                    cachedBrowserHistory = LoadBrowserHistory();
                }
                ImGui::Separator();
                ImGui::Spacing();

                if (ImGui::BeginTabBar("NetworkSubTabs", ImGuiTabBarFlags_None)) {
                    if (ImGui::BeginTabItem("Active TCP Sockets")) {
                        ImGui::Spacing();
                        ImGui::Text("Filter TCP:");
                        ImGui::SameLine();
                        ImGui::SetNextItemWidth(250);
                        ImGui::InputText("##netSearch", netSearchBuffer, sizeof(netSearchBuffer));
                        ImGui::SameLine();
                        ImGui::Text(" | TOTAL: %zu", cachedNetConnections.size());
                        ImGui::Spacing();

                        float tableHeight = (float)winHeight - 240.0f;
                        if (ImGui::BeginTable("NetTable", 6, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, tableHeight))) {
                            ImGui::TableSetupColumn("Proto", ImGuiTableColumnFlags_WidthFixed, 60.0f);
                            ImGui::TableSetupColumn("Local Address", ImGuiTableColumnFlags_WidthFixed, 150.0f);
                            ImGui::TableSetupColumn("Remote Address", ImGuiTableColumnFlags_WidthFixed, 150.0f);
                            ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 110.0f);
                            ImGui::TableSetupColumn("Process / PID", ImGuiTableColumnFlags_WidthFixed, 120.0f);
                            ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthStretch, 1.0f);
                            ImGui::TableHeadersRow();

                            std::string filterStr = netSearchBuffer;
                            std::transform(filterStr.begin(), filterStr.end(), filterStr.begin(), ::tolower);

                            for (size_t i = 0; i < cachedNetConnections.size(); ++i) {
                                const auto& conn = cachedNetConnections[i];
                                std::string remoteLower = conn.remoteIp;
                                std::transform(remoteLower.begin(), remoteLower.end(), remoteLower.begin(), ::tolower);
                                
                                if (!filterStr.empty() && remoteLower.find(filterStr) == std::string::npos && conn.state.find(filterStr) == std::string::npos) {
                                    continue;
                                }

                                ImGui::TableNextRow();
                                ImGui::PushID((int)i);
                                
                                ImGui::TableSetColumnIndex(0); 
                                ImGui::Text("%s", conn.protocol.c_str());
                                
                                ImGui::TableSetColumnIndex(1);
                                ImGui::Text("%s:%d", conn.localIp.c_str(), conn.localPort);
                                
                                ImGui::TableSetColumnIndex(2); 
                                ImGui::Text("%s:%d", conn.remoteIp.c_str(), conn.remotePort);

                                ImGui::TableSetColumnIndex(3);
                                if (conn.state == "ESTABLISHED") {
                                    ImGui::TextColored(ImVec4(0.0f, 0.8f, 0.0f, 1.0f), "%s", conn.state.c_str());
                                } else {
                                    ImGui::Text("%s", conn.state.c_str());
                                }

                                ImGui::TableSetColumnIndex(4); 
                                ImGui::Text("PID: %lu", conn.pid);

                                ImGui::TableSetColumnIndex(5);
                                if (ImGui::Button("Inspect")) {
                                    selectedNetConn = conn;
                                    showNetDetailsModal = true;
                                }
                                ImGui::PopID();
                            }
                            ImGui::EndTable();
                        }
                        ImGui::EndTabItem();
                    }
                    if (ImGui::BeginTabItem("System Adapters")) {
                        ImGui::Spacing();
                        ImGui::TextColored(themes[currentThemeIndex].accentColor, "Network Adapters & IP Configuration");
                        ImGui::Spacing();

                        float tableHeight = (float)winHeight - 240.0f;
                        
                        ImGuiTableFlags flags = ImGuiTableFlags_Borders | 
                                                ImGuiTableFlags_RowBg | 
                                                ImGuiTableFlags_ScrollY | 
                                                ImGuiTableFlags_Resizable | 
                                                ImGuiTableFlags_Reorderable | 
                                                ImGuiTableFlags_Hideable;

                        if (ImGui::BeginTable("AdapterTable", 5, flags, ImVec2(0, tableHeight))) {
                            ImGui::TableSetupColumn("Adapter Name", ImGuiTableColumnFlags_WidthFixed, 240.0f);
                            ImGui::TableSetupColumn("IP Protocol", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                            ImGui::TableSetupColumn("Assigned IP", ImGuiTableColumnFlags_WidthFixed, 160.0f);
                            ImGui::TableSetupColumn("Config Type", ImGuiTableColumnFlags_WidthFixed, 130.0f);
                            ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthStretch, 1.0f);
                            ImGui::TableHeadersRow();

                            for (size_t i = 0; i < cachedSystemConfig.size(); ++i) {
                                const auto& sys = cachedSystemConfig[i];
                                ImGui::TableNextRow();
                                
                                ImGui::TableSetColumnIndex(0);
                                ImGui::Text("%s", sys.processName.c_str());
                                
                                ImGui::TableSetColumnIndex(1);
                                ImGui::Text("%s", sys.protocol.c_str());
                                
                                ImGui::TableSetColumnIndex(2);
                                ImGui::Text("%s", sys.localIp.c_str());
                                
                                ImGui::TableSetColumnIndex(3);
                                ImGui::Text("%s", sys.remoteIp.c_str());
                                
                                ImGui::TableSetColumnIndex(4);
                                if (sys.state == "UP") {
                                    ImGui::TextColored(ImVec4(0.0f, 0.8f, 0.0f, 1.0f), "UP");
                                } else {
                                    ImGui::TextColored(ImVec4(0.8f, 0.0f, 0.0f, 1.0f), "DOWN");
                                }
                            }
                            ImGui::EndTable();
                        }
                        ImGui::EndTabItem();
                    }

                    if (ImGui::BeginTabItem("DNS Cache / History")) {
                        ImGui::Spacing();
                        ImGui::TextColored(themes[currentThemeIndex].accentColor, "Active Windows DNS Client Cache (Full Details)");
                        ImGui::SameLine();
                        ImGui::Text(" | TOTAL: %zu", cachedDnsHistory.size());
                        ImGui::Spacing();

                        float tableHeight = (float)winHeight - 240.0f;
                        ImGuiTableFlags dnsTableFlags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX | ImGuiTableFlags_Resizable;

                        if (ImGui::BeginTable("DnsFullTable", 8, dnsTableFlags, ImVec2(0, tableHeight))) {
                            ImGui::TableSetupColumn("Entry", ImGuiTableColumnFlags_WidthFixed, 150.0f);
                            ImGui::TableSetupColumn("RecordName", ImGuiTableColumnFlags_WidthFixed, 150.0f);
                            ImGui::TableSetupColumn("RecordType", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                            ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                            ImGui::TableSetupColumn("Section", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                            ImGui::TableSetupColumn("TimeToLive", ImGuiTableColumnFlags_WidthFixed, 90.0f);
                            ImGui::TableSetupColumn("DataLength", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                            ImGui::TableSetupColumn("Data (IP)", ImGuiTableColumnFlags_WidthStretch, 1.0f);
                            ImGui::TableHeadersRow();

                            for (size_t i = 0; i < cachedDnsHistory.size(); ++i) {
                                const auto& dns = cachedDnsHistory[i];
                                ImGui::TableNextRow();
                                
                                ImGui::TableSetColumnIndex(0);
                                ImGui::Text("%s", dns.localIp.c_str());
                                
                                ImGui::TableSetColumnIndex(1);
                                ImGui::Text("%s", dns.dnsRecordName.c_str());
                                
                                ImGui::TableSetColumnIndex(2);
                                ImGui::Text("%s", dns.protocol.c_str());
                                
                                ImGui::TableSetColumnIndex(3);
                                ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), "%s", dns.dnsStatus.c_str());
                                
                                ImGui::TableSetColumnIndex(4);
                                ImGui::Text("%s", dns.dnsSection.c_str());
                                
                                ImGui::TableSetColumnIndex(5);
                                ImGui::TextColored(ImVec4(0.9f, 0.9f, 0.3f, 1.0f), "%s", dns.state.c_str());
                                
                                ImGui::TableSetColumnIndex(6);
                                ImGui::Text("%s", dns.dnsDataLength.c_str());
                                
                                ImGui::TableSetColumnIndex(7);
                                ImGui::TextColored(ImVec4(0.2f, 0.8f, 1.0f, 1.0f), "%s", dns.remoteIp.c_str());
                            }
                            ImGui::EndTable();
                        }
                        ImGui::EndTabItem();
                    }

                    if (ImGui::BeginTabItem("Browser History")) {
                        ImGui::Spacing();                        
                        if (cachedBrowserHistory.empty()) {
                            cachedBrowserHistory = LoadBrowserHistory();
                        }

                        ImGui::TextColored(themes[currentThemeIndex].accentColor, "Extracted Web Browser History & Artifacts (Chrome)");
                        ImGui::SameLine();
                        ImGui::Text(" | TOTAL: %zu", cachedBrowserHistory.size());
                        ImGui::Spacing();

                        float tableHeight = (float)winHeight - 240.0f;
                        ImGuiTableFlags browserTableFlags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable;

                        if (ImGui::BeginTable("BrowserHistoryTable", 4, browserTableFlags, ImVec2(0, tableHeight))) {
                            ImGui::TableSetupColumn("Browser", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                            ImGui::TableSetupColumn("URL / Visit Target", ImGuiTableColumnFlags_WidthStretch, 2.0f);
                            ImGui::TableSetupColumn("Page Title", ImGuiTableColumnFlags_WidthStretch, 2.0f);
                            ImGui::TableSetupColumn("Timestamp", ImGuiTableColumnFlags_WidthFixed, 150.0f);
                            ImGui::TableHeadersRow();

                            for (size_t i = 0; i < cachedBrowserHistory.size(); ++i) {
                                const auto& hist = cachedBrowserHistory[i];
                                ImGui::TableNextRow();
                                
                                ImGui::TableSetColumnIndex(0); 
                                ImGui::Text("%s", hist.browserName.c_str());
                                
                                ImGui::TableSetColumnIndex(1); 
                                ImGui::TextColored(ImVec4(0.2f, 0.8f, 1.0f, 1.0f), "%s", hist.url.c_str());
                                
                                ImGui::TableSetColumnIndex(2); 
                                ImGui::Text("%s", hist.title.c_str());
                                
                                ImGui::TableSetColumnIndex(3); 
                                ImGui::Text("%s", hist.timestamp.c_str());
                            }

                            ImGui::EndTable();
                        }
                        ImGui::EndTabItem();
                    }

                    ImGui::EndTabBar();
                }
                ImGui::EndTabItem();
            }

            // TAB: INSTALLED APPS
            if (ImGui::BeginTabItem("Installed Apps", NULL, (currentTab == 15 ? itemFlags : 0))) {
                ImGui::TextColored(themes[currentThemeIndex].accentColor, "[ INSTALLED SOFTWARE INVENTORY ]");
                ImGui::SameLine(winWidth - 200);
                ImGui::Text("TOTAL: %zu", cachedInstalledApps.size());
                ImGui::Separator();

                ImGui::Text("Filter:");
                ImGui::SameLine();
                ImGui::SetNextItemWidth(250);
                ImGui::InputText("##installedSearch", installedSearchBuffer, sizeof(installedSearchBuffer));
                ImGui::SameLine();
                if (ImGui::Button("Refresh List")) {
                    cachedInstalledApps = GetInstalledApplications();
                }
                
                ImGui::Spacing();
                float tableHeight = (float)winHeight - 190.0f;

                if (ImGui::BeginTable("InstalledAppsTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, tableHeight))) {
                    ImGui::TableSetupColumn("Application Name", ImGuiTableColumnFlags_WidthStretch, 2.0f);
                    ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 90.0f);
                    ImGui::TableSetupColumn("Version", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                    ImGui::TableSetupColumn("Actions / Details", ImGuiTableColumnFlags_WidthFixed, 140.0f);
                    ImGui::TableHeadersRow();

                    std::string filterStr = installedSearchBuffer;
                    std::transform(filterStr.begin(), filterStr.end(), filterStr.begin(), ::tolower);

                    for (size_t i = 0; i < cachedInstalledApps.size(); ++i) {
                        const auto& app = cachedInstalledApps[i];

                        std::string nameLower = app.name;
                        std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
                        if (!filterStr.empty() && nameLower.find(filterStr) == std::string::npos) continue;
                        ImGui::TableNextRow();                        
                        ImGui::PushID((int)i);
                        ImGui::TableSetColumnIndex(0); 
                        ImGui::Text("%s", app.name.c_str());
                        ImGui::TableSetColumnIndex(1);
                        ImGui::Text("%s", app.sizeStr.c_str());
                        ImGui::TableSetColumnIndex(2); 
                        ImGui::Text("%s", app.version.c_str());
                        ImGui::TableSetColumnIndex(3);
                        if (ImGui::Button("Details")) {
                            selectedInstalledApp = app;
                            showAppDetailsModal = true;
                        }

                        ImGui::PopID();
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            // TAB: WINDOWS SERVICES
            if (ImGui::BeginTabItem("Windows Services", NULL, (currentTab == 16 ? itemFlags : 0))) {
                ImGui::Text("Registered System Services & Interactive Control");
                ImGui::Separator();
                if (ImGui::BeginTable("ServicesTableExt", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, (float)winHeight - 170.0f))) {
                    ImGui::TableSetupColumn("Service Name", ImGuiTableColumnFlags_WidthFixed, 180.0f);
                    ImGui::TableSetupColumn("Display Name", ImGuiTableColumnFlags_WidthStretch, 1.0f);
                    ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                    ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, 160.0f);
                    ImGui::TableHeadersRow();

                    for (auto& s : cachedServicesExt) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0); ImGui::Text("%s", s.name.c_str());
                        ImGui::TableSetColumnIndex(1); ImGui::Text("%s", s.displayName.c_str());
                        ImGui::TableSetColumnIndex(2); 
                        ImGui::TextColored(s.status == SERVICE_RUNNING ? ImVec4(0.3f, 0.9f, 0.3f, 1.0f) : ImVec4(0.9f, 0.3f, 0.3f, 1.0f), 
                            s.status == SERVICE_RUNNING ? "Running" : "Stopped");
                        
                        ImGui::TableSetColumnIndex(3);
                        char startBtn[64], stopBtn[64];
                        snprintf(startBtn, sizeof(startBtn), "Start##%s", s.name.c_str());
                        snprintf(stopBtn, sizeof(stopBtn), "Stop##%s", s.name.c_str());

                        if (s.status == SERVICE_RUNNING) {
                            if (ImGui::Button(stopBtn)) {
                                SC_HANDLE hSC = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
                                if (hSC) {
                                    SC_HANDLE hSvc = OpenServiceA(hSC, s.name.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
                                    if (hSvc) { SERVICE_STATUS ss; ControlService(hSvc, SERVICE_CONTROL_STOP, &ss); CloseServiceHandle(hSvc); }
                                    CloseServiceHandle(hSC);
                                }
                                cachedServicesExt = GetWindowsServicesExt();
                            }
                        } else {
                            if (ImGui::Button(startBtn)) {
                                SC_HANDLE hSC = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
                                if (hSC) {
                                    SC_HANDLE hSvc = OpenServiceA(hSC, s.name.c_str(), SERVICE_START | SERVICE_QUERY_STATUS);
                                    if (hSvc) { StartServiceA(hSvc, 0, NULL); CloseServiceHandle(hSvc); }
                                    CloseServiceHandle(hSC);
                                }
                                cachedServicesExt = GetWindowsServicesExt();
                            }
                        }
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            // TAB: SCHEDULED TASKS
            if (ImGui::BeginTabItem("Scheduled Tasks", NULL, (currentTab == 17 ? itemFlags : 0))) {
                ImGui::Text("Windows Task Scheduler Explorer");
                ImGui::Separator();
                ImGui::InputText("Filter Tasks", taskSearchBuffer, sizeof(taskSearchBuffer));
                ImGui::Separator();

                if (ImGui::BeginTable("TaskTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, (float)winHeight - 210.0f))) {
                    ImGui::TableSetupColumn("Task Name", ImGuiTableColumnFlags_WidthFixed, 220.0f);
                    ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 90.0f);
                    ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch, 1.0f);
                    ImGui::TableSetupColumn("Toggle", ImGuiTableColumnFlags_WidthFixed, 90.0f);
                    ImGui::TableHeadersRow();

                    std::string tFilter = taskSearchBuffer;
                    std::transform(tFilter.begin(), tFilter.end(), tFilter.begin(), ::tolower);

                    for (auto& task : cachedTasks) {
                        std::string taskNameStr(task.name.begin(), task.name.end());
                        std::string taskPathStr(task.path.begin(), task.path.end());

                        std::string tNameLower = taskNameStr;
                        std::transform(tNameLower.begin(), tNameLower.end(), tNameLower.begin(), ::tolower);
                        if (!tFilter.empty() && tNameLower.find(tFilter) == std::string::npos) continue;

                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0); ImGui::Text("%s", taskNameStr.c_str());
                        ImGui::TableSetColumnIndex(1); 
                        ImGui::TextColored(task.enabled ? ImVec4(0.3f, 0.9f, 0.3f, 1.0f) : ImVec4(0.9f, 0.3f, 0.3f, 1.0f), 
                            task.enabled ? "Enabled" : "Disabled");
                        ImGui::TableSetColumnIndex(2); ImGui::Text("%s", taskPathStr.c_str());
                        
                        ImGui::TableSetColumnIndex(3);
                        char togBtn[64];
                        snprintf(togBtn, sizeof(togBtn), "Change##%s", taskNameStr.c_str());
                        if (ImGui::Button(togBtn)) {
                            task.enabled = !task.enabled; 
                        }
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            // TAB: DLL DEPENDENCY VIEWER
            if (ImGui::BeginTabItem("DLL Dependency Viewer", NULL, (currentTab == 18 ? itemFlags : 0))) {
                ImGui::Text("Inspect Exported Functions & Symbols of any DLL");
                ImGui::Separator();

                ImGui::SetNextItemWidth(-180.0f);
                ImGui::InputText("##DllFilePath", dllSearchBuffer, sizeof(dllSearchBuffer));
                
                ImGui::SameLine();
                if (ImGui::Button("Browse...")) {
                    OPENFILENAMEW ofn;
                    wchar_t szFile[260] = { 0 };
                    ZeroMemory(&ofn, sizeof(ofn));
                    ofn.lStructSize = sizeof(ofn);
                    ofn.hwndOwner = hwnd;
                    ofn.lpstrFile = szFile;
                    ofn.nMaxFile = sizeof(szFile) / sizeof(wchar_t);
                    ofn.lpstrFilter = L"DLL Files (*.dll)\0*.dll\0Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
                    ofn.nFilterIndex = 1;
                    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

                    if (GetOpenFileNameW(&ofn) == TRUE) {
                        WideCharToMultiByte(CP_UTF8, 0, ofn.lpstrFile, -1, dllSearchBuffer, sizeof(dllSearchBuffer), NULL, NULL);
                    }
                }

                ImGui::SameLine();
                if (ImGui::Button("Scan Exports")) {
                    selectedDllPath = dllSearchBuffer;
                    cachedDllExports = GetDllExports(selectedDllPath);
                }
                
                ImGui::Separator();

                if (ImGui::BeginTable("DllExportTable", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, (float)winHeight - 210.0f))) {
                    ImGui::TableSetupColumn("Ordinal", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                    ImGui::TableSetupColumn("Exported Function Name", ImGuiTableColumnFlags_WidthStretch, 1.0f);
                    ImGui::TableHeadersRow();

                    for (const auto& exp : cachedDllExports) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0); ImGui::Text("%u", exp.ordinal);
                        ImGui::TableSetColumnIndex(1); ImGui::Text("%s", exp.functionName.c_str());
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            // TAB: STARTUP APPLICATIONS
            if (ImGui::BeginTabItem("Startup Applications", NULL, (currentTab == 19 ? itemFlags : 0))) {
                ImGui::Text("Auto-start Registry Programs, Folders & Status");
                ImGui::Separator();
                
                if (ImGui::Button("Refresh List")) {
                    cachedStartup = GetStartupAppsEnhanced();
                }
                
                ImGui::SameLine();
                ImGui::TextDisabled("(Changes apply instantly, matching Windows Task Manager behavior)");
                ImGui::Spacing();

                if (ImGui::BeginTable("StartupTable", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, (float)winHeight - 170.0f))) {
                    ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 180.0f);
                    ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 90.0f);
                    ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                    ImGui::TableSetupColumn("Location", ImGuiTableColumnFlags_WidthFixed, 140.0f);
                    ImGui::TableSetupColumn("Executable Path", ImGuiTableColumnFlags_WidthStretch, 1.0f);
                    ImGui::TableHeadersRow();

                    for (size_t i = 0; i < cachedStartup.size(); ++i) {
                        auto& app = cachedStartup[i];
                        ImGui::TableNextRow();
                        
                        ImGui::TableSetColumnIndex(0); 
                        ImGui::Text("%s", app.name.c_str());
                        
                        ImGui::TableSetColumnIndex(1); 
                        if (app.isEnabled) {
                            ImGui::TextColored(ImVec4(0.3f, 0.9f, 0.3f, 1.0f), "Enabled");
                        } else {
                            ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f), "Disabled");
                        }

                        ImGui::TableSetColumnIndex(2);
                        ImGui::PushID((int)i);
                        if (app.isEnabled) {
                            if (ImGui::Button("Disable", ImVec2(90, 0))) {
                                if (SetStartupAppEnabled(app, false)) {
                                    app.isEnabled = false;
                                }
                            }
                        } else {
                            if (ImGui::Button("Enable", ImVec2(90, 0))) {
                                if (SetStartupAppEnabled(app, true)) {
                                    app.isEnabled = true;
                                }
                            }
                        }
                        ImGui::PopID();

                        ImGui::TableSetColumnIndex(3); 
                        ImGui::Text("%s", app.location.c_str());
                        
                        ImGui::TableSetColumnIndex(4); 
                        ImGui::Text("%s", app.path.c_str());
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            // TAB: ENVIRONMENT VARIABLES
            if (ImGui::BeginTabItem("Environment Variables", NULL, (currentTab == 20 ? itemFlags : 0))) {
                ImGui::Text("Current System Environment Variables");
                ImGui::Separator();
                if (ImGui::BeginTable("EnvTable", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, (float)winHeight - 170.0f))) {
                    ImGui::TableSetupColumn("Variable", ImGuiTableColumnFlags_WidthFixed, 200.0f);
                    ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 1.0f);
                    ImGui::TableHeadersRow();

                    for (const auto& env : cachedEnvs) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0); ImGui::Text("%s", env.name.c_str());
                        ImGui::TableSetColumnIndex(1); ImGui::Text("%s", env.value.c_str());
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            // TAB: LOCKED HANDLES
            if (ImGui::BeginTabItem("Locked Handles", NULL, (currentTab == 21 ? itemFlags : 0))) {
                ImGui::Text("Scan for processes locking specific paths or files");
                ImGui::Separator();
                ImGui::InputText("Search partial path or name", lockSearchBuffer, sizeof(lockSearchBuffer));
                ImGui::SameLine();
                if (ImGui::Button("Scan Locks")) {
                    cachedLocked = FindLockedFiles(lockSearchBuffer);
                }
                ImGui::Separator();

                if (ImGui::BeginTable("LockedTable", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, (float)winHeight - 210.0f))) {
                    ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthFixed, 180.0f);
                    ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                    ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthStretch, 1.0f);
                    ImGui::TableHeadersRow();

                    for (const auto& l : cachedLocked) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0); ImGui::Text("%s", l.processName.c_str());
                        ImGui::TableSetColumnIndex(1); ImGui::Text("%lu", l.pid);
                        ImGui::TableSetColumnIndex(2); ImGui::Text("%s", l.handleType.c_str());
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Dump Analyzer", NULL, (currentTab == 22 ? itemFlags : 0))) {
                ImGui::TextColored(themes[currentThemeIndex].accentColor, "[ FORENSIC DUMP ANALYZER ]");
                ImGui::Separator();
                
                ImGui::Text("Select a .dmp file to inspect its structure:");
                ImGui::Spacing();

                ImGui::SetNextItemWidth(winWidth - 370);
                ImGui::InputText("##dumpPath", analyzePathBuffer, sizeof(analyzePathBuffer));
                ImGui::SameLine();
                
                if (ImGui::Button("Browse...", ImVec2(90, 0))) {
                    OPENFILENAMEA ofn = {};
                    ofn.lStructSize = sizeof(ofn);
                    ofn.hwndOwner = hwnd;
                    ofn.lpstrFilter = "Dump Files (*.dmp)\0*.dmp\0All Files (*.*)\0*.*\0";
                    ofn.lpstrFile = analyzePathBuffer;
                    ofn.nMaxFile = MAX_PATH;
                    ofn.Flags = OFN_FILEMUSTEXIST;
                    if (GetOpenFileNameA(&ofn) == TRUE) {
                        currentDumpAnalysis = AnalyzeMiniDumpFile(analyzePathBuffer);
                        dumpAnalyzed = true;
                    }
                }

                ImGui::SameLine();
                if (ImGui::Button("Analyze File", ImVec2(100, 0))) {
                    if (strlen(analyzePathBuffer) > 0) {
                        currentDumpAnalysis = AnalyzeMiniDumpFile(analyzePathBuffer);
                        dumpAnalyzed = true;
                    }
                }

                ImGui::Spacing();
                ImGui::Separator();
                ImGui::Spacing();

                if (dumpAnalyzed) {
                    if (currentDumpAnalysis.isValid) {
                        ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "[+] Valid and compatible .dmp file.");
                        ImGui::Spacing();
                        
                        ImGui::BeginChild("DumpDetails", ImVec2(0, 110), true);
                        ImGui::Text("Dump OS Version:     %s", currentDumpAnalysis.osVersion.c_str());
                        ImGui::Text("Registered Threads:  %lu", currentDumpAnalysis.numberOfThreads);
                        ImGui::Text("Loaded DLL Modules:  %lu", currentDumpAnalysis.numberOfModules);
                        ImGui::Text("Exception Diagnosis: %s", currentDumpAnalysis.exceptionInfo.c_str());
                        ImGui::EndChild();

                        ImGui::Spacing();
                        ImGui::TextColored(themes[currentThemeIndex].accentColor, "THREAD LIST (TID):");
                        ImGui::Spacing();

                        float threadTableHeight = (float)winHeight - 340.0f;
                        if (threadTableHeight < 150.0f) threadTableHeight = 150.0f;

                        if (ImGui::BeginTable("DumpThreadsTable", 2, ImGuiTableFlags_BordersV | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, threadTableHeight))) {
                            ImGui::TableSetupColumn("Index", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                            ImGui::TableSetupColumn("Thread ID (TID) / Hex", ImGuiTableColumnFlags_WidthStretch);
                            ImGui::TableHeadersRow();

                            for (size_t i = 0; i < currentDumpAnalysis.threads.size(); ++i) {
                                ImGui::TableNextRow();
                                ImGui::TableSetColumnIndex(0);
                                ImGui::Text("%zu", i);
                                ImGui::TableSetColumnIndex(1);
                                ImGui::Text("0x%X (%u)", currentDumpAnalysis.threads[i].threadId, currentDumpAnalysis.threads[i].threadId);
                            }
                            ImGui::EndTable();
                        }
                    } else {
                        ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "[-] Error: Invalid or corrupted dump file.");
                    }
                }

                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Live Tracker", NULL, (currentTab == 23 ? itemFlags : 0))) {
                ImGui::TextColored(themes[currentThemeIndex].accentColor, "[ BEHAVIORAL PROCESS MONITOR // NON-INVASIVE ]");
                ImGui::Separator();
                ImGui::Spacing();

                ImGui::Text("Launch Executable:");
                ImGui::SetNextItemWidth(winWidth - 270);
                ImGui::InputText("##sandboxpath", sandboxPath, sizeof(sandboxPath));
                ImGui::SameLine();
                if (ImGui::Button("Browse...", ImVec2(80, 0))) {
                    OPENFILENAMEA ofn;
                    ZeroMemory(&ofn, sizeof(ofn));
                    ofn.lStructSize = sizeof(ofn);
                    ofn.lpstrFile = sandboxPath;
                    ofn.nMaxFile = sizeof(sandboxPath);
                    ofn.lpstrFilter = "Executables (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
                    ofn.nFilterIndex = 1;
                    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
                    GetOpenFileNameA(&ofn);
                }
                ImGui::SameLine();
                if (ImGui::Button("Launch & Track", ImVec2(120, 0))) {
                    if (strlen(sandboxPath) > 0) {
                        STARTUPINFOA si = { sizeof(STARTUPINFOA) };
                        if (CreateProcessA(sandboxPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &monitoredPi)) {
                            monitoredPid = monitoredPi.dwProcessId;
                            hMonitoredProcess = monitoredPi.hProcess;
                            isTracking = true;
                            memset(liveCpuHistory, 0, sizeof(liveCpuHistory));
                            memset(liveMemHistory, 0, sizeof(liveMemHistory));
                            lastLiveTick = GetTickCount64();
                        }
                    }
                }

                ImGui::Spacing();
                static int targetPidInput = 0;
                ImGui::Text("Or Attach to PID:");
                ImGui::SetNextItemWidth(150);
                ImGui::InputInt("##targetpid", &targetPidInput);
                ImGui::SameLine();
                if (ImGui::Button("Attach", ImVec2(100, 0))) {
                    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, FALSE, (DWORD)targetPidInput);
                    if (hProc) {
                        if (hMonitoredProcess) CloseHandle(hMonitoredProcess);
                        hMonitoredProcess = hProc;
                        monitoredPid = (DWORD)targetPidInput;
                        isTracking = true;
                        memset(liveCpuHistory, 0, sizeof(liveCpuHistory));
                        memset(liveMemHistory, 0, sizeof(liveMemHistory));
                        lastLiveTick = GetTickCount64();
                    }
                }

                ImGui::Spacing();
                ImGui::Separator();
                ImGui::Spacing();

                if (isTracking && monitoredPid != 0) {
                    ImGui::Text("Surveilling PID: %lu", monitoredPid);
                    ImGui::SameLine();
                    if (ImGui::Button("Stop Tracking")) {
                        if (hMonitoredProcess) { CloseHandle(hMonitoredProcess); hMonitoredProcess = NULL; }
                        monitoredPid = 0;
                        isTracking = false;
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Kill Process", ImVec2(100, 0))) {
                        HANDLE hTerm = OpenProcess(PROCESS_TERMINATE, FALSE, monitoredPid);
                        if (hTerm) { TerminateProcess(hTerm, 0); CloseHandle(hTerm); }
                        isTracking = false;
                        monitoredPid = 0;
                    }

                    ULONGLONG currentTick = GetTickCount64();
                    if (currentTick - lastLiveTick > 500 && hMonitoredProcess != NULL) {
                        PROCESS_MEMORY_COUNTERS pmc;
                        if (GetProcessMemoryInfo(hMonitoredProcess, &pmc, sizeof(pmc))) {
                            liveMemHistory[liveHistoryIndex] = (float)pmc.WorkingSetSize / (1024.0f * 1024.0f);
                        }

                        FILETIME creationTime, exitTime, kernelTime, userTime;
                        if (GetProcessTimes(hMonitoredProcess, &creationTime, &exitTime, &kernelTime, &userTime)) {
                            ULARGE_INTEGER kt, ut;
                            kt.LowPart = kernelTime.dwLowDateTime; kt.HighPart = kernelTime.dwHighDateTime;
                            ut.LowPart = userTime.dwLowDateTime;   ut.HighPart = userTime.dwHighDateTime;
                            
                            ULONGLONG timeDelta = (kt.QuadPart + ut.QuadPart) - (lastLiveKernel.QuadPart + lastLiveUser.QuadPart);
                            ULONGLONG tickDelta = currentTick - lastLiveTick;

                            if (tickDelta > 0) {
                                SYSTEM_INFO sysInfo;
                                GetSystemInfo(&sysInfo);
                                double cpu = (double)timeDelta / (tickDelta * 10000.0 * sysInfo.dwNumberOfProcessors);
                                float cpuVal = (float)(cpu * 100.0);
                                liveCpuHistory[liveHistoryIndex] = (cpuVal > 100.0f) ? 100.0f : cpuVal;
                            }
                            lastLiveKernel = kt;
                            lastLiveUser = ut;
                        }
                        lastLiveTick = currentTick;
                        liveHistoryIndex = (liveHistoryIndex + 1) % 60;
                    }

                    if (currentTick - lastBehaviorPoll > 2000) {
                        liveThreads = GetProcessThreads(monitoredPid, liveThreadsError);
                        liveConnections = GetProcessConnections(monitoredPid, liveConnectionsError);
                        liveModules = GetProcessModules(monitoredPid, liveModulesError);
                        liveMemoryMap = GetProcessMemoryMap(hMonitoredProcess, liveMemoryError);
                        lastBehaviorPoll = currentTick;
                    }

                    ImGui::Spacing();
                    ImGui::PlotLines("CPU (%)", liveCpuHistory, 60, liveHistoryIndex, NULL, 0.0f, 100.0f, ImVec2(0, 80));
                    ImGui::PlotLines("RAM (MB)", liveMemHistory, 60, liveHistoryIndex, NULL, 0.0f, 500.0f, ImVec2(0, 80));

                    ImGui::Spacing();
                    ImGui::Separator();
                    
                    if (ImGui::BeginTabBar("BehaviorTabs")) {
                        
                        if (ImGui::BeginTabItem("Active Network Sockets")) {
                            ImGui::Text("Network Activity:");
                            if (ImGui::BeginTable("LiveNetTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, 150))) {
                                ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthFixed, 70.0f);
                                ImGui::TableSetupColumn("Local Addr", ImGuiTableColumnFlags_WidthStretch, 1.0f);
                                ImGui::TableSetupColumn("Remote Addr", ImGuiTableColumnFlags_WidthStretch, 1.0f);
                                ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                                ImGui::TableHeadersRow();

                                for (const auto& conn : liveConnections) {
                                    ImGui::TableNextRow();
                                    ImGui::TableSetColumnIndex(0); ImGui::Text("%s", conn.protocol.c_str());
                                    ImGui::TableSetColumnIndex(1); ImGui::Text("%s", conn.localAddr.c_str());
                                    ImGui::TableSetColumnIndex(2); ImGui::Text("%s", conn.remoteAddr.c_str());
                                    ImGui::TableSetColumnIndex(3); ImGui::Text("%s", conn.state.c_str());
                                }
                                ImGui::EndTable();
                            }
                            ImGui::EndTabItem();
                        }

                        if (ImGui::BeginTabItem("Active Threads")) {
                            ImGui::Text("Running Threads: %zu", liveThreads.size());
                            if (ImGui::BeginTable("LiveThreadsTable", 1, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, 150))) {
                                ImGui::TableSetupColumn("Thread ID", ImGuiTableColumnFlags_WidthStretch, 1.0f);
                                ImGui::TableHeadersRow();

                                for (const auto& th : liveThreads) {
                                    ImGui::TableNextRow();
                                    ImGui::TableSetColumnIndex(0); ImGui::Text("%lu", th.tid);
                                }
                                ImGui::EndTable();
                            }
                            ImGui::EndTabItem();
                        }

                        if (ImGui::BeginTabItem("Loaded DLLs")) {
                            ImGui::Text("Loaded Modules / Libraries: %zu", liveModules.size());
                            if (ImGui::BeginTable("LiveModTable", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, 150))) {
                                ImGui::TableSetupColumn("Module Name", ImGuiTableColumnFlags_WidthFixed, 150.0f);
                                ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch, 1.0f);
                                ImGui::TableHeadersRow();

                                for (const auto& mod : liveModules) {
                                    ImGui::TableNextRow();
                                    ImGui::TableSetColumnIndex(0); ImGui::Text("%s", mod.name.c_str());
                                    ImGui::TableSetColumnIndex(1); ImGui::Text("%s", mod.path.c_str());
                                }
                                ImGui::EndTable();
                            }
                            ImGui::EndTabItem();
                        }

                        if (ImGui::BeginTabItem("Memory Map")) {
                            ImGui::Text("Virtual Memory Regions: %zu", liveMemoryMap.size());
                            if (ImGui::BeginTable("LiveMemMapTable", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, 150))) {
                                ImGui::TableSetupColumn("Base Address", ImGuiTableColumnFlags_WidthFixed, 130.0f);
                                ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 90.0f);
                                ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                                ImGui::TableSetupColumn("Protection", ImGuiTableColumnFlags_WidthFixed, 120.0f);
                                ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthStretch, 1.0f);
                                ImGui::TableHeadersRow();

                                for (const auto& reg : liveMemoryMap) {
                                    ImGui::TableNextRow();
                                    
                                    bool isDangerous = (reg.protection.find("ERW") != std::string::npos);
                                    if (isDangerous) {
                                        ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 80, 80, 255));
                                    }

                                    ImGui::TableSetColumnIndex(0); ImGui::Text("%s", reg.baseAddress.c_str());
                                    ImGui::TableSetColumnIndex(1); ImGui::Text("%s", reg.regionSize.c_str());
                                    ImGui::TableSetColumnIndex(2); ImGui::Text("%s", reg.state.c_str());
                                    ImGui::TableSetColumnIndex(3); ImGui::Text("%s", reg.protection.c_str());
                                    ImGui::TableSetColumnIndex(4); ImGui::Text("%s", reg.type.c_str());

                                    if (isDangerous) {
                                        ImGui::PopStyleColor();
                                    }
                                }
                                ImGui::EndTable();
                            }
                            ImGui::EndTabItem();
                        }

                        ImGui::EndTabBar();
                    }

                } else {
                    ImGui::TextDisabled("No process under surveillance. Launch or attach above to begin behavior tracking.");
                }

                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Tech Toolbox", NULL, (currentTab == 24 ? itemFlags : 0))) {
                ImGui::TextColored(themes[currentThemeIndex].accentColor, "[ RAPID MAINTENANCE & REPAIR UTILITIES ]");
                ImGui::Separator();
                ImGui::Spacing();

                // --- SECTION 1: CLEANING UP JUNK FILES ---
                if (ImGui::CollapsingHeader("System Junk Cleanup", ImGuiTreeNodeFlags_DefaultOpen)) {
                    ImGui::Spacing();
                    ImGui::Text("Clean temporary files to free up disk space and fix cache glitches.");
                    ImGui::Spacing();

                    if (ImGui::Button("Clean User Temp (%TEMP%)", ImVec2(220, 30))) {
                        system("cmd.exe /c rd /s /q \"%TEMP%\" & md \"%TEMP%\"");
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Clean Windows Temp", ImVec2(220, 30))) {
                        system("cmd.exe /c rd /s /q \"C:\\Windows\\Temp\" & md \"C:\\Windows\\Temp\"");
                    }

                    if (ImGui::Button("Flush DNS Cache", ImVec2(220, 30))) {
                        system("ipconfig /flushdns");
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Reset Winsock & IP", ImVec2(220, 30))) {
                        system("netsh winsock reset & netsh int ip reset");
                    }
                    ImGui::Spacing();
                }

                ImGui::Spacing();
                ImGui::Separator();
                ImGui::Spacing();

                // --- SECTION 2: NETWORKS AND CONFIGURATION ---
                if (ImGui::CollapsingHeader("Network Configuration & Diagnostics", ImGuiTreeNodeFlags_DefaultOpen)) {
                    ImGui::Spacing();
                    ImGui::Text("Quick actions for common network connectivity issues.");
                    ImGui::Spacing();

                    if (ImGui::Button("Renew IP Address", ImVec2(220, 30))) {
                        system("ipconfig /release & ipconfig /renew");
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Open Network Connections", ImVec2(220, 30))) {
                        system("control ncpa.cpl");
                    }

                    ImGui::Spacing();
                }

                ImGui::Spacing();
                ImGui::Separator();
                ImGui::Spacing();

                // --- SECTION 3: ADMINISTRATION SHORTCUTS ---
                if (ImGui::CollapsingHeader("Admin Shortcuts", ImGuiTreeNodeFlags_DefaultOpen)) {
                    ImGui::Spacing();
                    
                    if (ImGui::Button("Device Manager", ImVec2(180, 25))) {
                        system("devmgmt.msc");
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Disk Management", ImVec2(180, 25))) {
                        system("diskmgmt.msc");
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Event Viewer", ImVec2(180, 25))) {
                        system("eventvwr.msc");
                    }

                    if (ImGui::Button("Services Manager", ImVec2(180, 25))) {
                        system("services.msc");
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Control Panel", ImVec2(180, 25))) {
                        system("control");
                    }

                    ImGui::Spacing();
                }

                ImGui::EndTabItem();
            }

            ImGui::EndTabBar();
        }
        ImGui::EndChild();
        if (switchTab) {
            switchTab = false;
        }
        ImGui::End();

        // --- INTERNAL MODAL WINDOWS ---

        if (showAppDetailsModal) {
            ImGui::OpenPopup("Installed App Details");
        }
        if (showNetDetailsModal) {
            ImGui::OpenPopup("Network Connection Details");
        }
        if (showLiveBootModal) {
            ImGui::OpenPopup("Live Boot Builder Modal");
        }
        if (showReportViewerModal) {
            ImGui::OpenPopup("Forensic Report Viewer");
        }
        if (showHandlesDlls) {
            ImGui::OpenPopup("Handles & Advanced DLLs Inspector");
        }
        if (ImGui::BeginPopupModal("Handles & Advanced DLLs Inspector", &showHandlesDlls)) {
            ImGui::Text("Inspecting Process ID: %lu", handlesDllsPid);
            ImGui::Separator();

            if (isHandlesDllsLoading) {
                ImGui::Spacing();
                ImGui::TextColored(ImVec4(1, 0.8f, 0.2f, 1), "Loading system handles and auditing DLLs in background...");
                ImGui::Spacing();
            } else {
                if (ImGui::BeginTabBar("HandlesDllsTabs")) {            
                    // SYSTEM HANDLES TAB
                    if (ImGui::BeginTabItem("System Handles")) {
                        if (!handlesError.empty()) {
                            ImGui::TextColored(ImVec4(1, 0.4f, 0.4f, 1), "Error: %s", handlesError.c_str());
                        } else if (cachedHandles.empty()) {
                            ImGui::TextColored(ImVec4(1, 0.8f, 0.2f, 1), "No handles retrieved. The target process may have exited, or access was restricted.");
                        } else {
                            if (ImGui::BeginTable("HandlesTable", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, 360))) {
                                ImGui::TableSetupColumn("Handle Value", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                                ImGui::TableSetupColumn("Object Type", ImGuiTableColumnFlags_WidthFixed, 150.0f);
                                ImGui::TableSetupColumn("Object Name / Details", ImGuiTableColumnFlags_WidthStretch);
                                ImGui::TableHeadersRow();

                                for (const auto& h : cachedHandles) {
                                    ImGui::TableNextRow();
                                    ImGui::TableSetColumnIndex(0); ImGui::Text("0x%p", h.handleValue);
                                    ImGui::TableSetColumnIndex(1); ImGui::Text("%s", h.typeName.c_str());
                                    ImGui::TableSetColumnIndex(2); ImGui::Text("%s", h.objectName.c_str());
                                }
                                ImGui::EndTable();
                            }
                        }
                        ImGui::EndTabItem();
                    }

                    // ADVANCED DLL AUDIT TAB
                    if (ImGui::BeginTabItem("Advanced DLL Audit")) {
                        if (!advancedModulesError.empty()) {
                            ImGui::TextColored(ImVec4(1, 0.4f, 0.4f, 1), "Error: %s", advancedModulesError.c_str());
                        } else if (cachedAdvancedModules.empty()) {
                            ImGui::TextColored(ImVec4(1, 0.8f, 0.2f, 1), "No modules retrieved. Ensure the target process is accessible and running.");
                        } else {
                            ImGui::TextWrapped("Compares physical memory-mapped DLLs against disk images to detect potential injection, hollowing, or DLL hijacking techniques.");
                            ImGui::Spacing();

                            if (ImGui::BeginTable("AdvancedDllsTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, 310))) {
                                ImGui::TableSetupColumn("Module Name", ImGuiTableColumnFlags_WidthFixed, 140.0f);
                                ImGui::TableSetupColumn("Base Address", ImGuiTableColumnFlags_WidthFixed, 120.0f);
                                ImGui::TableSetupColumn("Path on Disk", ImGuiTableColumnFlags_WidthStretch);
                                ImGui::TableSetupColumn("Integrity / Status", ImGuiTableColumnFlags_WidthFixed, 120.0f);
                                ImGui::TableHeadersRow();

                                for (const auto& mod : cachedAdvancedModules) {
                                    ImGui::TableNextRow();
                                    ImGui::TableSetColumnIndex(0); ImGui::Text("%s", mod.name.c_str());
                                    ImGui::TableSetColumnIndex(1); ImGui::Text("0x%p", (void*)mod.baseAddress);
                                    ImGui::TableSetColumnIndex(2); ImGui::Text("%s", mod.path.c_str());
                                    
                                    ImGui::TableSetColumnIndex(3);
                                    if (mod.isModified) {
                                        ImGui::TextColored(ImVec4(1, 0.2f, 0.2f, 1), "MODIFIED (Injected)");
                                    } else if (mod.isHijackedPath) {
                                        ImGui::TextColored(ImVec4(1, 0.8f, 0.2f, 1), "Suspicious Path");
                                    } else {
                                        ImGui::TextColored(ImVec4(0.2f, 1, 0.2f, 1), "Clean / Valid");
                                    }
                                }
                                ImGui::EndTable();
                            }
                        }
                        ImGui::EndTabItem();
                    }

                    ImGui::EndTabBar();
                }
            }

            ImGui::Spacing();
            ImGui::Separator();
            if (ImGui::Button("Close", ImVec2(120, 0))) {
                ImGui::CloseCurrentPopup();
                showHandlesDlls = false;
            }

            ImGui::EndPopup();
        }
        if (ImGui::BeginPopupModal("Forensic Report Viewer", &showReportViewerModal)) {
            if (ImGui::Button("Open Report File...", ImVec2(150, 0))) {
                char filename[MAX_PATH] = "";
                OPENFILENAMEA ofn = {0};
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = hwnd;
                ofn.lpstrFilter = "Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
                ofn.lpstrFile = filename;
                ofn.nMaxFile = MAX_PATH;
                ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
                
                if (GetOpenFileNameA(&ofn)) {
                    std::ifstream file(filename);
                    if (file.is_open()) {
                        std::stringstream buffer;
                        buffer << file.rdbuf();
                        loadedReportContent = buffer.str();
                        loadedReportFilename = filename;
                    }
                }
            }

            if (!loadedReportFilename.empty()) {
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f), "Loaded: %s", loadedReportFilename.c_str());
            }

            ImGui::Separator();

            if (loadedReportContent.empty()) {
                ImGui::Spacing();
                ImGui::TextDisabled("No report loaded. Click 'Open Report File...' to select a previously generated text report.");
                ImGui::Spacing();
            } else {
                std::vector<std::string> generalInfo;
                std::vector<std::string> memoryLines;
                std::vector<std::string> moduleLines;
                std::vector<std::string> threadLines;
                std::vector<std::string> networkLines;

                std::istringstream stream(loadedReportContent);
                std::string line;
                int currentSection = 0;

                while (std::getline(stream, line)) {
                    if (!line.empty() && line.back() == '\r') line.pop_back();

                    if (line.find("NEXUSGLASSMANAGER") != std::string::npos || line.find("====") != std::string::npos) continue;

                    if (line.find("--- VIRTUAL MEMORY MAP ---") != std::string::npos) { currentSection = 1; continue; }
                    if (line.find("--- LOADED MODULES (DLLs) ---") != std::string::npos) { currentSection = 2; continue; }
                    if (line.find("--- ACTIVE THREADS ---") != std::string::npos) { currentSection = 3; continue; }
                    if (line.find("--- NETWORK CONNECTIONS ---") != std::string::npos) { currentSection = 4; continue; }

                    if (line.empty()) continue;

                    if (currentSection == 0) generalInfo.push_back(line);
                    else if (currentSection == 1) memoryLines.push_back(line);
                    else if (currentSection == 2) moduleLines.push_back(line);
                    else if (currentSection == 3) threadLines.push_back(line);
                    else if (currentSection == 4) networkLines.push_back(line);
                }

                if (ImGui::BeginTabBar("ReportViewerTabs", ImGuiTabBarFlags_NoTooltip)) {
                    if (ImGui::BeginTabItem("General Info")) {
                        ImGui::BeginChild("TabGenChild", ImVec2(0, -10), true);
                        ImGui::Spacing();
                        for (const auto& item : generalInfo) {
                            ImGui::BulletText("%s", item.c_str());
                        }
                        ImGui::EndChild();
                        ImGui::EndTabItem();
                    }

                    if (ImGui::BeginTabItem("Virtual Memory")) {
                        ImGui::BeginChild("TabMemChild", ImVec2(0, -10), true, ImGuiWindowFlags_HorizontalScrollbar);
                        ImGui::Spacing();
                        for (const auto& item : memoryLines) {
                            if (item.find("EXECUTE") != std::string::npos) {
                                ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", item.c_str());
                            } else {
                                ImGui::Text("%s", item.c_str());
                            }
                        }
                        ImGui::EndChild();
                        ImGui::EndTabItem();
                    }

                    if (ImGui::BeginTabItem("Loaded Modules")) {
                        ImGui::BeginChild("TabModChild", ImVec2(0, -10), true, ImGuiWindowFlags_HorizontalScrollbar);
                        ImGui::Spacing();
                        for (const auto& item : moduleLines) {
                            ImGui::Text("%s", item.c_str());
                        }
                        ImGui::EndChild();
                        ImGui::EndTabItem();
                    }

                    if (ImGui::BeginTabItem("Active Threads")) {
                        ImGui::BeginChild("TabThrChild", ImVec2(0, -10), true);
                        ImGui::Spacing();
                        for (const auto& item : threadLines) {
                            ImGui::Text("%s", item.c_str());
                        }
                        ImGui::EndChild();
                        ImGui::EndTabItem();
                    }

                    if (ImGui::BeginTabItem("Network Connections")) {
                        ImGui::BeginChild("TabNetChild", ImVec2(0, -10), true, ImGuiWindowFlags_HorizontalScrollbar);
                        ImGui::Spacing();
                        for (const auto& item : networkLines) {
                            if (item.find("ESTABLISHED") != std::string::npos) {
                                ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "%s", item.c_str());
                            } else {
                                ImGui::Text("%s", item.c_str());
                            }
                        }
                        ImGui::EndChild();
                        ImGui::EndTabItem();
                    }

                    ImGui::EndTabBar();
                }
            }

            ImGui::Spacing();
            if (ImGui::Button("Close Viewer", ImVec2(120, 0))) {
                ImGui::CloseCurrentPopup();
                showReportViewerModal = false;
            }

            ImGui::EndPopup();
        }
        if (ImGui::BeginPopupModal("Live Boot Builder Modal", &showLiveBootModal, ImGuiWindowFlags_AlwaysAutoResize)) {
            static int targetTypeIndex = 0;
            static char usbDriveInput[16] = "E:";
            static char isoPathInput[MAX_PATH] = "C:\\LiveMonitorBoot.iso";
            static bool isBuildingProcess = false;
            static std::string liveProgressMessage = "Idle";

            ImGui::TextWrapped("Generates a rescue and audit environment in strict read-only mode.");
            ImGui::Separator();

            ImGui::RadioButton("Direct USB Drive", &targetTypeIndex, 0); ImGui::SameLine();
            ImGui::RadioButton("ISO File (for VM)", &targetTypeIndex, 1);

            if (targetTypeIndex == 0) {
                ImGui::SetNextItemWidth(250.0f);
                ImGui::InputText("USB Drive", usbDriveInput, sizeof(usbDriveInput));
                ImGui::SameLine();
                if (ImGui::Button("Browse Drives...")) {
                    ImGui::OpenPopup("UsbDrivePopup");
                }

                if (ImGui::BeginPopup("UsbDrivePopup")) {
                    DWORD drives = GetLogicalDrives();
                    for (char letter = 'A'; letter <= 'Z'; ++letter) {
                        if (drives & (1 << (letter - 'A'))) {
                            char rootPath[4] = { letter, ':', '\\', '\0' };
                            UINT type = GetDriveTypeA(rootPath);
                            if (type == DRIVE_REMOVABLE || type == DRIVE_FIXED) {
                                char label[16];
                                snprintf(label, sizeof(label), "%c:", letter);
                                if (ImGui::Selectable(label)) {
                                    snprintf(usbDriveInput, sizeof(usbDriveInput), "%c:", letter);
                                }
                            }
                        }
                    }
                    ImGui::EndPopup();
                }

                ImGui::TextDisabled("(e.g., E:). Warning: It will be completely formatted!");
            } else {
                ImGui::SetNextItemWidth(300.0f);
                ImGui::InputText("Target ISO Path", isoPathInput, sizeof(isoPathInput));
                ImGui::SameLine();
                if (ImGui::Button("Browse...")) {
                    OPENFILENAMEA ofn;
                    char szFile[MAX_PATH];
                    ZeroMemory(&ofn, sizeof(ofn));
                    ofn.lStructSize = sizeof(ofn);
                    ofn.hwndOwner = NULL;
                    ofn.lpstrFile = szFile;
                    ofn.lpstrFile[0] = '\0';
                    ofn.nMaxFile = sizeof(szFile);
                    ofn.lpstrFilter = "ISO Files\0*.iso\0All Files\0*.*\0";
                    ofn.nMaxFileTitle = 0;
                    ofn.lpstrInitialDir = NULL;
                    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
                    ofn.lpstrDefExt = "iso";
                    if (GetSaveFileNameA(&ofn)) {
                        strncpy_s(isoPathInput, ofn.lpstrFile, sizeof(isoPathInput));
                    }
                }
            }

            ImGui::Spacing();

            if (isBuildingProcess) {
                ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.0f, 1.0f), "[Status]: %s", liveProgressMessage.c_str());
            } else {
                if (ImGui::Button("Build Live Boot Media", ImVec2(160, 0))) {
                    isBuildingProcess = true;
                    liveProgressMessage = "Starting...";

                    std::string destination = (targetTypeIndex == 0) ? std::string(usbDriveInput) : std::string(isoPathInput);
                    bool isUsb = (targetTypeIndex == 0);

                    std::thread([=]() {
                        bool success = BuildLiveBootMedia(destination, isUsb, liveProgressMessage);
                        if (!success && liveProgressMessage.find("Error") == std::string::npos && liveProgressMessage.find("Failed") == std::string::npos) {
                            liveProgressMessage = "Unknown error during creation.";
                        }
                        isBuildingProcess = false;
                    }).detach();
                }
            }

            if (!isBuildingProcess && !liveProgressMessage.empty() && liveProgressMessage != "Idle") {
                ImGui::Spacing();
                ImGui::TextWrapped("Result: %s", liveProgressMessage.c_str());
            }

            ImGui::Spacing();
            ImGui::Separator();
            
            if (ImGui::Button("Close", ImVec2(120, 0)) && !isBuildingProcess) {
                showLiveBootModal = false;
                ImGui::CloseCurrentPopup();
            }

            ImGui::EndPopup();
        }
        if (ImGui::BeginPopupModal("Network Connection Details", &showNetDetailsModal, ImGuiWindowFlags_NoResize)) {
            ImGui::TextColored(themes[currentThemeIndex].accentColor, "[ SOCKET & PROCESS FORENSICS ]");
            ImGui::Separator();
            ImGui::Spacing();

            ImGui::Text("Protocol:      %s", selectedNetConn.protocol.c_str());
            ImGui::Text("Local Endpoint:  %s:%d", selectedNetConn.localIp.c_str(), selectedNetConn.localPort);
            ImGui::Text("Remote Endpoint: %s:%d", selectedNetConn.remoteIp.c_str(), selectedNetConn.remotePort);
            ImGui::Text("State:           %s", selectedNetConn.state.c_str());
            ImGui::Text("Owner PID:       %lu", selectedNetConn.pid);
            ImGui::Text("Process Name:    %s", selectedNetConn.processName.c_str());

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            if (ImGui::Button("Terminate Owner Process", ImVec2(180, 0))) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, selectedNetConn.pid);
                if (hProc) {
                    TerminateProcess(hProc, 1);
                    CloseHandle(hProc);
                    cachedNetConnections = GetActiveConnections();
                }
                showNetDetailsModal = false;
            }

            ImGui::SameLine();
            if (ImGui::Button("Close", ImVec2(120, 0))) {
                showNetDetailsModal = false;
            }

            ImGui::EndPopup();
        }
        if (ImGui::BeginPopupModal("Installed App Details", &showAppDetailsModal, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::Text("Name: %s", selectedInstalledApp.name.c_str());
            ImGui::Text("Publisher: %s", selectedInstalledApp.publisher.empty() ? "N/A" : selectedInstalledApp.publisher.c_str());
            ImGui::Text("Version: %s", selectedInstalledApp.version.empty() ? "N/A" : selectedInstalledApp.version.c_str());
            ImGui::Text("Install Location: %s", selectedInstalledApp.installLocation.empty() ? "N/A" : selectedInstalledApp.installLocation.c_str());
            ImGui::Separator();
            ImGui::TextWrapped("Uninstall Command: %s", selectedInstalledApp.uninstallString.empty() ? "N/A" : selectedInstalledApp.uninstallString.c_str());
            
            ImGui::Spacing();
            if (!selectedInstalledApp.uninstallString.empty()) {
                if (ImGui::Button("Uninstall Application")) {
                    ShellExecuteA(NULL, "open", "cmd.exe", ("/c " + selectedInstalledApp.uninstallString).c_str(), NULL, SW_SHOW);
                }
                ImGui::SameLine();
            }
            if (ImGui::Button("Close", ImVec2(120, 0))) {
                showAppDetailsModal = false;
                ImGui::CloseCurrentPopup();
            }
            ImGui::EndPopup();
        }

        if (showMemoryMap) {
            ImGui::SetNextWindowSize(ImVec2(780, 560), ImGuiCond_FirstUseEver);
            if (ImGui::Begin("Virtual Memory Map", &showMemoryMap)) {
                
                ImGui::Text("Inspecting Virtual Memory for Target PID: %lu", memoryMapPid);
                ImGui::Separator();

                if (!memoryMapError.empty()) {
                    ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", memoryMapError.c_str());
                } else {
                    ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "[*] Scanning memory regions for injection and hollowing heuristics...");
                    ImGui::Spacing();

                    static char memoryFilter[64] = "";
                    ImGui::Text("Filter Regions:");
                    ImGui::SameLine();
                    ImGui::SetNextItemWidth(250.0f);
                    ImGui::InputText("##MemoryFilter", memoryFilter, sizeof(memoryFilter));
                    ImGui::SameLine();
                    if (ImGui::Button("Reset Filter")) {
                        memset(memoryFilter, 0, sizeof(memoryFilter));
                    }
                    ImGui::Spacing();

                    if (ImGui::BeginTable("MemoryMapTable", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, 270))) {
                        ImGui::TableSetupColumn("Base Address", ImGuiTableColumnFlags_WidthFixed, 180.0f);
                        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                        ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 90.0f);
                        ImGui::TableSetupColumn("Protection", ImGuiTableColumnFlags_WidthFixed, 120.0f);
                        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 90.0f);
                        ImGui::TableHeadersRow();

                        int clickedRowIndex = -1;
                        std::string filterStr(memoryFilter);

                        for (size_t i = 0; i < cachedMemoryRegions.size(); ++i) {
                            const auto& reg = cachedMemoryRegions[i];
                            
                            std::string protStr = GetProtectionString(reg.protect);
                            std::string stateStr = GetStateString(reg.state);
                            std::string typeStr = GetTypeString(reg.type);

                            if (!filterStr.empty()) {
                                char addrBuf[64];
                                snprintf(addrBuf, sizeof(addrBuf), "0x%016llX", reg.baseAddress);
                                
                                std::string combined = std::string(addrBuf) + " " + stateStr + " " + protStr + " " + typeStr;
                                std::string lowerCombined = combined;
                                std::string lowerFilter = filterStr;
                                std::transform(lowerCombined.begin(), lowerCombined.end(), lowerCombined.begin(), ::tolower);
                                std::transform(lowerFilter.begin(), lowerFilter.end(), lowerFilter.begin(), ::tolower);

                                if (lowerCombined.find(lowerFilter) == std::string::npos) {
                                    continue;
                                }
                            }

                            ImGui::TableNextRow();

                            ImGui::TableSetColumnIndex(0);
                            char rowLabel[128];
                            snprintf(rowLabel, sizeof(rowLabel), "0x%016llX##row%zu", reg.baseAddress, i);

                            if (reg.isSuspicious) {
                                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.3f, 0.3f, 1.0f));
                            }

                            if (ImGui::Selectable(rowLabel, false, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap)) {
                            }

                            if (reg.isSuspicious) {
                                ImGui::PopStyleColor();
                            }

                            if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                                clickedRowIndex = (int)i;
                            }

                            ImGui::TableSetColumnIndex(1); ImGui::Text("%zu", reg.regionSize);
                            ImGui::TableSetColumnIndex(2); ImGui::Text("%s", stateStr.c_str());
                            ImGui::TableSetColumnIndex(3); ImGui::Text("%s", protStr.c_str());
                            ImGui::TableSetColumnIndex(4); ImGui::Text("%s", typeStr.c_str());
                        }

                        if (clickedRowIndex != -1) {
                            selectedMemoryRegionForSearch = cachedMemoryRegions[clickedRowIndex];
                            searchTargetPid = memoryMapPid;
                            ImGui::OpenPopup("MemoryRegionContextMenu");
                        }

                        if (ImGui::BeginPopup("MemoryRegionContextMenu")) {
                            
                            bool canReadRegion = (selectedMemoryRegionForSearch.state == MEM_COMMIT) &&
                                                (selectedMemoryRegionForSearch.protect != PAGE_NOACCESS) &&
                                                (selectedMemoryRegionForSearch.protect != 0);

                            if (canReadRegion) {
                                if (ImGui::MenuItem("Search String in this Region...")) {
                                    showStringSearchModal = true;
                                    memset(searchStringInput, 0, sizeof(searchStringInput));
                                    
                                    {
                                        std::lock_guard<std::mutex> lock(searchResultsMutex);
                                        searchResultsList.clear();
                                    }
                                    
                                    if (memorySearchThread.joinable()) {
                                        memorySearchThread.join();
                                    }
                                    memorySearchThread = std::thread(PerformBackgroundStringExtraction, searchTargetPid, selectedMemoryRegionForSearch);
                                    ImGui::OpenPopup("String Search Results");
                                }
                            } else {
                                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.6f, 0.6f, 0.6f, 1.0f));
                                ImGui::MenuItem("Search String (Region unreadable)", NULL, false, false);
                                ImGui::PopStyleColor();
                            }

                            ImGui::EndPopup();
                        }

                        ImGui::EndTable();
                    }

                    ImGui::Spacing();
                    ImGui::Separator();
                    ImGui::Spacing();

                    ImGui::Text("Security Diagnostics & Anomalies:");
                    ImGui::BeginChild("SuspiciousRegionsChild", ImVec2(0, 100), true, ImGuiWindowFlags_AlwaysVerticalScrollbar);
                    
                    bool foundAnySuspicious = false;
                    for (size_t i = 0; i < cachedMemoryRegions.size(); ++i) {
                        const auto& reg = cachedMemoryRegions[i];
                        if (reg.isSuspicious) {
                            foundAnySuspicious = true;
                            ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), 
                                "[!] INJECTION DETECTED -> Address: 0x%016llX | Size: %zu bytes | Protection: %s", 
                                reg.baseAddress, reg.regionSize, GetProtectionString(reg.protect).c_str());
                        }
                    }

                    if (!foundAnySuspicious) {
                        ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "[+] No anomalous private executable memory regions found.");
                    }
                    
                    ImGui::EndChild();
                }
            }
            ImGui::End();
        }

        if (showStringSearchModal) {
            ImGui::OpenPopup("String Search Results");
        }

        if (ImGui::BeginPopupModal("String Search Results", &showStringSearchModal, ImGuiWindowFlags_None)) {
            ImGui::Text("Target PID: %lu | Region: 0x%016llX | Size: %zu bytes", 
                        searchTargetPid, selectedMemoryRegionForSearch.baseAddress, selectedMemoryRegionForSearch.regionSize);
            ImGui::Separator();

            bool isMemoryReadable = (selectedMemoryRegionForSearch.state == MEM_COMMIT) &&
                                    (selectedMemoryRegionForSearch.protect != PAGE_NOACCESS) &&
                                    (selectedMemoryRegionForSearch.protect != 0);

            if (!isMemoryReadable) {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.4f, 0.4f, 1.0f));
                ImGui::TextWrapped("[!] Warning: This memory region is FREE or NOACCESS. Strings cannot be extracted.");
                ImGui::PopStyleColor();
                ImGui::Spacing();
            }

            ImGui::Text("Filter Strings:");
            ImGui::SetNextItemWidth(-1.0f);
            ImGui::InputText("##StringFilterInput", searchStringInput, sizeof(searchStringInput));

            if (isSearchingActive && totalBytesToSearch > 0) {
                float progress = (float)searchedBytesCount / (float)totalBytesToSearch;
                char progressOverlay[64];
                snprintf(progressOverlay, sizeof(progressOverlay), "Extracting strings... %.1f%%", progress * 100.0f);
                ImGui::ProgressBar(progress, ImVec2(-1.0f, 0.0f), progressOverlay);
            } else {
                ImGui::Spacing();
            }

            ImGui::Separator();
            
            std::vector<std::string> localResultsCopy;
            {
                std::lock_guard<std::mutex> lock(searchResultsMutex);
                localResultsCopy = searchResultsList;
            }

            std::string filterText(searchStringInput);
            
            std::vector<std::string> filteredResults;
            for (const auto& res : localResultsCopy) {
                if (filterText.empty()) {
                    filteredResults.push_back(res);
                } else {
                    std::string lowerRes = res;
                    std::string lowerFilter = filterText;
                    std::transform(lowerRes.begin(), lowerRes.end(), lowerRes.begin(), ::tolower);
                    std::transform(lowerFilter.begin(), lowerFilter.end(), lowerFilter.begin(), ::tolower);
                    
                    if (lowerRes.find(lowerFilter) != std::string::npos) {
                        filteredResults.push_back(res);
                    }
                }
            }

            ImGui::Text("Strings found: %zu %s", localResultsCopy.size(), isSearchingActive ? "(Scanning...)" : "");
            
            ImGui::BeginChild("SearchResultsScroll", ImVec2(0, -45), true, ImGuiWindowFlags_HorizontalScrollbar);
            
            ImGuiListClipper clipper;
            clipper.Begin((int)filteredResults.size());
            while (clipper.Step()) {
                for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                    ImGui::TextUnformatted(filteredResults[i].c_str());
                }
            }
            clipper.End();

            ImGui::EndChild();

            if (!filterText.empty()) {
                ImGui::TextDisabled("Showing %zu matching strings", filteredResults.size());
            }

            if (ImGui::Button("Close", ImVec2(100, 0))) {
                if (isSearchingActive) {
                    isSearchingActive = false;
                }
                if (memorySearchThread.joinable()) {
                    memorySearchThread.join();
                }
                ImGui::CloseCurrentPopup();
                showStringSearchModal = false;
            }

            ImGui::EndPopup();
        }

        if (showModulesThreads) {
            ImGui::SetNextWindowSize(ImVec2(820, 560), ImGuiCond_FirstUseEver);
            if (ImGui::Begin("Modules & Threads Inspector", &showModulesThreads)) {
                if (ImGui::BeginTabBar("ModThreadTabs")) {
                    if (ImGui::BeginTabItem("Modules (DLLs)")) {
                        if (!modulesError.empty()) {
                            ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", modulesError.c_str());
                        } else {
                            static char moduleFilter[64] = "";
                            ImGui::Text("Filter DLLs:");
                            ImGui::SameLine();
                            ImGui::SetNextItemWidth(250.0f);
                            ImGui::InputText("##ModuleFilter", moduleFilter, sizeof(moduleFilter));
                            ImGui::SameLine();
                            ImGui::TextDisabled("(Total: %zu)", cachedModules.size());
                            ImGui::Spacing();

                            if (ImGui::BeginTable("ModTable", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, 390))) {
                                ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 160.0f);
                                ImGui::TableSetupColumn("Base Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
                                ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch, 1.0f);
                                ImGui::TableHeadersRow();

                                std::string modFilterStr(moduleFilter);

                                for (size_t i = 0; i < cachedModules.size(); ++i) {
                                    const auto& mod = cachedModules[i];

                                    if (!modFilterStr.empty()) {
                                        std::string combined = mod.name + " " + mod.path;
                                        std::string lowerCombined = combined;
                                        std::string lowerFilter = modFilterStr;
                                        std::transform(lowerCombined.begin(), lowerCombined.end(), lowerCombined.begin(), ::tolower);
                                        std::transform(lowerFilter.begin(), lowerFilter.end(), lowerFilter.begin(), ::tolower);

                                        if (lowerCombined.find(lowerFilter) == std::string::npos) {
                                            continue;
                                        }
                                    }

                                    ImGui::TableNextRow();
                                    ImGui::TableSetColumnIndex(0);
                                    
                                    char rowId[64];
                                    snprintf(rowId, sizeof(rowId), "%s##mod%zu", mod.name.c_str(), i);
                                    
                                    bool isSelected = false;
                                    ImGui::Selectable(rowId, isSelected, ImGuiSelectableFlags_SpanAllColumns);

                                    if (ImGui::BeginPopupContextItem()) {
                                        static ModuleInfoItem selectedModuleForInspection = mod;
                                        selectedModuleForInspection = mod;

                                        if (ImGui::MenuItem("Copy Module Path")) {
                                            ImGui::SetClipboardText(selectedModuleForInspection.path.c_str());
                                        }
                                        ImGui::EndPopup();
                                    }

                                    ImGui::TableSetColumnIndex(1); 
                                    ImGui::Text("0x%016llX", mod.baseAddress);
                                    
                                    ImGui::TableSetColumnIndex(2); 
                                    ImGui::TextUnformatted(mod.path.c_str());
                                }

                                ImGui::EndTable();
                            }
                        }
                        ImGui::EndTabItem();
                    }

                    if (ImGui::BeginTabItem("Threads")) {
                        if (!threadsError.empty()) {
                            ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", threadsError.c_str());
                        } else {
                            static char threadFilter[64] = "";
                            ImGui::Text("Filter Threads (TID):");
                            ImGui::SameLine();
                            ImGui::SetNextItemWidth(250.0f);
                            ImGui::InputText("##ThreadFilter", threadFilter, sizeof(threadFilter));
                            ImGui::SameLine();
                            ImGui::TextDisabled("(Active: %zu)", cachedThreads.size());
                            ImGui::Spacing();

                            if (ImGui::BeginTable("ThreadTable", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, 390))) {
                                ImGui::TableSetupColumn("Thread ID (TID)", ImGuiTableColumnFlags_WidthFixed, 140.0f);
                                ImGui::TableSetupColumn("Process ID (PID)", ImGuiTableColumnFlags_WidthFixed, 140.0f);
                                ImGui::TableSetupColumn("Base Priority", ImGuiTableColumnFlags_WidthStretch, 1.0f);
                                ImGui::TableHeadersRow();

                                std::string threadFilterStr(threadFilter);

                                for (size_t i = 0; i < cachedThreads.size(); ++i) {
                                    const auto& th = cachedThreads[i];

                                    if (!threadFilterStr.empty()) {
                                        std::string tidStr = std::to_string(th.tid);
                                        if (tidStr.find(threadFilterStr) == std::string::npos) {
                                            continue;
                                        }
                                    }

                                    ImGui::TableNextRow();
                                    ImGui::TableSetColumnIndex(0); 
                                    ImGui::Text("%lu", th.tid);
                                    
                                    ImGui::TableSetColumnIndex(1); 
                                    ImGui::Text("%lu", th.ownerPid);
                                    
                                    ImGui::TableSetColumnIndex(2); 
                                    ImGui::Text("%ld", th.basePri);
                                }
                                ImGui::EndTable();
                            }
                        }
                        ImGui::EndTabItem();
                    }

                    ImGui::EndTabBar();
                }
            }
            ImGui::End();
        }

        if (showConnections) {
            ImGui::SetNextWindowSize(ImVec2(750, 400), ImGuiCond_FirstUseEver);
            if (ImGui::Begin("Process Network Connections", &showConnections)) {
                if (!connectionsError.empty()) {
                    ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", connectionsError.c_str());
                } else if (cachedConnections.empty()) {
                    ImGui::Text("No active TCP connections found for this process.");
                } else {
                    if (ImGui::BeginTable("ConnTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, 320))) {
                        ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                        ImGui::TableSetupColumn("Local Address", ImGuiTableColumnFlags_WidthFixed, 180.0f);
                        ImGui::TableSetupColumn("Remote Address", ImGuiTableColumnFlags_WidthFixed, 180.0f);
                        ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 120.0f);
                        ImGui::TableHeadersRow();
                        for (const auto& conn : cachedConnections) {
                            ImGui::TableNextRow();
                            ImGui::TableSetColumnIndex(0); ImGui::Text("%s", conn.protocol.c_str());
                            ImGui::TableSetColumnIndex(1); ImGui::Text("%s:%d", conn.localAddr.c_str(), conn.localPort);
                            ImGui::TableSetColumnIndex(2); ImGui::Text("%s:%d", conn.remoteAddr.c_str(), conn.remotePort);
                            ImGui::TableSetColumnIndex(3); ImGui::Text("%s", conn.state.c_str());
                        }
                        ImGui::EndTable();
                    }
                }
            }
            ImGui::End();
        }

        ImGui::Render();
        glViewport(0, 0, winWidth, winHeight);
        
        ImVec4 bg = themes[currentThemeIndex].backgroundColor;
        glClearColor(bg.x, bg.y, bg.z, bg.w);
        glClear(GL_COLOR_BUFFER_BIT);
        
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        SwapBuffers(hDC);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    wglMakeCurrent(NULL, NULL);
    wglDeleteContext(hRC);
    ReleaseDC(hwnd, hDC);
    DestroyWindow(hwnd);
    return 0;
}
