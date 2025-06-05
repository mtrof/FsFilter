#ifndef __FILTERDRIVER_H__
#define __FILTERDRIVER_H__

#define CONFIG_FILE_PATH L"\\Device\\HarddiskVolume3\\FilterDriver\\config.txt"

#define CONFIG_BUF_TAG   'CfgD'
#define PROCESS_NAME_TAG 'cpnt'
#define GROUP_NAME_TAG   'grpN'
#define PROCESS_INFO_TAG 'ipgD'

typedef NTSTATUS(*QUERY_INFO_PROCESS) (
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength
);

#define MAX_PATH 256
#define MAX_ROLES_COUNT 10

typedef enum _ACCESS_RIGHTS {
    READ = 0x01,
    WRITE = 0x02,
    EXECUTE = 0x04
} ACCESS_RIGHTS;

typedef struct _USER_ROLE {
    WCHAR RoleSid[256];
    ACCESS_RIGHTS Permissions;
} USER_ROLE;

typedef struct _FILE_ACCESS_CONFIG {
    WCHAR ProgramPath[MAX_PATH];
    WCHAR DirectoryPath[MAX_PATH];
    USER_ROLE Roles[MAX_ROLES_COUNT];
    ULONG RoleCount;
} FILE_ACCESS_CONFIG;

NTSTATUS ReadConfigFile(
    FILE_ACCESS_CONFIG* ConfigData
);

DRIVER_INITIALIZE DriverEntry;

NTSTATUS DriverEntry(
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
);

NTSTATUS UnloadCallback(
    __in FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS SetupCallback(
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_SETUP_FLAGS Flags,
    __in DEVICE_TYPE VolumeDeviceType,
    __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

FLT_PREOP_CALLBACK_STATUS PreOperationCallback(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS PostOperationCallback(
    IN OUT PFLT_CALLBACK_DATA Data,
    IN PCFLT_RELATED_OBJECTS FltObjects,
    IN PVOID CompletionContext,
    IN FLT_POST_OPERATION_FLAGS Flags
);

BOOLEAN IsPrefix(
    WCHAR* Prefix, WCHAR* FullString
);

BOOLEAN ComparePaths(
    WCHAR* PNorm, WCHAR* PHard, BOOLEAN PrefixComp
);

NTSTATUS GetProcessImageName(
    PUNICODE_STRING ProcessImageName
);

NTSTATUS GetUserGroups(
    PFLT_CALLBACK_DATA Data,
    PUNICODE_STRING MatchedGroupName
);

#endif