#include <fltKernel.h>
#include <suppress.h>

#include "FilterDriver.h"

FILE_ACCESS_CONFIG Config;

PFLT_FILTER Filter;
QUERY_INFO_PROCESS ZwQueryInformationProcess;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, UnloadCallback)
#pragma alloc_text(PAGE, SetupCallback)
#pragma alloc_text(PAGE, PreOperationCallback)
#pragma alloc_text(PAGE, PostOperationCallback)
#pragma alloc_text(PAGE, GetProcessImageName)
#pragma alloc_text(PAGE, GetUserGroups)
#endif

const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, PreOperationCallback, PostOperationCallback },
    { IRP_MJ_READ,   0, PreOperationCallback, PostOperationCallback },
    { IRP_MJ_WRITE,  0, PreOperationCallback, PostOperationCallback },
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0, NULL, 
    Callbacks, 
    UnloadCallback, SetupCallback,
    NULL, NULL, NULL,
    NULL, NULL, NULL,
    NULL, NULL, NULL
};

NTSTATUS ReadConfigFile(FILE_ACCESS_CONFIG* ConfigData)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE fileHandle = NULL;
    OBJECT_ATTRIBUTES objAttrs;
    IO_STATUS_BLOCK ioStatus;
    PVOID buffer = NULL;
    ULONG bufferSize = 4096, bytesRead = 0;
    WCHAR line[1024];
    UNICODE_STRING fileName, tempString;

    KEVENT event;

    int lineIndex = 0;

    RtlInitUnicodeString(&fileName, CONFIG_FILE_PATH);
    InitializeObjectAttributes(&objAttrs, &fileName, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(&fileHandle, GENERIC_READ,
        &objAttrs, &ioStatus, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("Failed to open config file\n");
        return status;
    }

    buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, CONFIG_BUF_TAG);
    if (!buffer)
    {
        ZwClose(fileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    status = ZwReadFile(fileHandle,
        NULL, NULL, NULL,
        &ioStatus, buffer, bufferSize,
        NULL, NULL);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = ioStatus.Status;
    }

    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(buffer, CONFIG_BUF_TAG);
        ZwClose(fileHandle);
        return status;
    }

    bytesRead += 2;
    while (bytesRead < ioStatus.Information && lineIndex - 2 < MAX_ROLES_COUNT)
    {
        RtlZeroMemory(line, sizeof(line));

        WCHAR* curPtr = (WCHAR*)((ULONG_PTR)buffer + bytesRead);
        int copySize = 0;
        WCHAR* tmpPtr = curPtr;
        while (1)
        {
            if (*tmpPtr == L'\r' && *(tmpPtr + 1) == L'\n') break;
            copySize++;
            tmpPtr++;
        }

        if (copySize == 0) continue;

        RtlCopyMemory(line, curPtr, copySize * sizeof(WCHAR));
        line[copySize] = UNICODE_NULL;

        bytesRead += (wcslen(line) + 2) * sizeof(WCHAR);

        if (lineIndex == 0)
        {
            RtlCopyMemory(ConfigData->ProgramPath, line, 256);
        }
        else if (lineIndex == 1)
        {
            RtlCopyMemory(ConfigData->DirectoryPath, line, 256);
        }
        else
        {
            int roleIndex = lineIndex - 2;

            RtlInitUnicodeString(&tempString, line + 4);
            RtlCopyMemory(ConfigData->Roles[roleIndex].RoleSid, tempString.Buffer, 256);
            
            line[3] = UNICODE_NULL;
            RtlInitUnicodeString(&tempString, line);
                    
            ACCESS_RIGHTS permissions = 0;
            if (wcschr(tempString.Buffer, L'r')) permissions |= READ;
            if (wcschr(tempString.Buffer, L'w')) permissions |= WRITE;
            if (wcschr(tempString.Buffer, L'x')) permissions |= EXECUTE;
            ConfigData->Roles[roleIndex].Permissions = permissions;
        }

        lineIndex++;
    }

    ExFreePoolWithTag(buffer, CONFIG_BUF_TAG);
    ZwClose(fileHandle);

    ConfigData->RoleCount = lineIndex - 2;
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(__in PDRIVER_OBJECT DriverObject, __in PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    status = ReadConfigFile(&Config);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("Failed to parse config file\n");
        return status;
    }

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &Filter);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("Filter not registered\n");
        return status;
    }

    status = FltStartFiltering(Filter);
    if (!NT_SUCCESS(status))
    {
        FltUnregisterFilter(Filter);
        DbgPrint("Filter not registered\n");
        return status;
    }

    DbgPrint("Filter registered\n");
    return STATUS_SUCCESS;
}

NTSTATUS UnloadCallback(__in FLT_FILTER_UNLOAD_FLAGS Flags)
{
    FltUnregisterFilter(Filter);
    DbgPrint("Filter unregistered\n");
    return STATUS_SUCCESS;
}

NTSTATUS SetupCallback(__in PCFLT_RELATED_OBJECTS FltObjects, __in FLT_INSTANCE_SETUP_FLAGS Flags,
    __in DEVICE_TYPE VolumeDeviceType, __in FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    ASSERT(FltObjects->Filter == Filter);

    if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM)
    {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS PreOperationCallback(__inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID* CompletionContext)
{
    NTSTATUS status;
    BOOLEAN denyOp = FALSE;

    if (FltObjects->FileObject == NULL || Data == NULL)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (FltObjects->FileObject->Flags & (FO_NAMED_PIPE | FO_MAILSLOT | FO_VOLUME_OPEN))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (FsRtlIsPagingFile(FltObjects->FileObject))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    UNICODE_STRING processName;
    UNICODE_STRING groupName;

    processName.Length = 0;
    processName.MaximumLength = 254 * sizeof(WCHAR);
    processName.Buffer = ExAllocatePoolWithTag(
        NonPagedPool, processName.MaximumLength, PROCESS_NAME_TAG);
    RtlZeroMemory(processName.Buffer, processName.MaximumLength);

    GetProcessImageName(&processName);

    groupName.Length = 0;
    groupName.MaximumLength = 254 * sizeof(WCHAR);
    groupName.Buffer = ExAllocatePoolWithTag(
        NonPagedPool, groupName.MaximumLength, GROUP_NAME_TAG);
    RtlZeroMemory(groupName.Buffer, groupName.MaximumLength);

    if (processName.Length == 0)
    {
        ExFreePoolWithTag(processName.Buffer, PROCESS_NAME_TAG);
        ExFreePoolWithTag(groupName.Buffer, GROUP_NAME_TAG);

        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    WCHAR* configProgramPath = Config.ProgramPath;
    WCHAR* realProgramPath = processName.Buffer;

    if (!ComparePaths(configProgramPath, realProgramPath, FALSE))
    {
        PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

        status = FltGetFileNameInformation(
            Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo
        );

        if (status != STATUS_SUCCESS)
        {
            if (nameInfo != NULL)
                FltReleaseFileNameInformation(nameInfo);

            ExFreePoolWithTag(processName.Buffer, PROCESS_NAME_TAG);
            ExFreePoolWithTag(groupName.Buffer, GROUP_NAME_TAG);

            return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        }

        FltParseFileNameInformation(nameInfo);

        WCHAR* configDirectoryPath = Config.DirectoryPath;
        WCHAR* realDirectoryPath = (nameInfo->Name).Buffer;

        if (!ComparePaths(configDirectoryPath, realDirectoryPath, TRUE))
        {
            ACCESS_MASK desiredAccess;

            GetUserGroups(Data, &groupName);

            if (Data->Iopb->MajorFunction == IRP_MJ_CREATE)
            {
                desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
            }

            for (int i = 0; i < Config.RoleCount; i++)
            {
                if (!wcscmp(Config.Roles[i].RoleSid, groupName.Buffer))
                {
                    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE)
                    {
                        if (desiredAccess & FILE_READ_DATA)
                        {
                            if (!(Config.Roles[i].Permissions & READ)) denyOp = TRUE;

                            DbgPrint("Role Sid: %ws\n", groupName.Buffer);
                            DbgPrint("Object: %ws\n", realDirectoryPath);

                            if (!denyOp) DbgPrint("Operation: READ    - Status: ALLOWED");
                            else DbgPrint("Operation: READ    - Status: BLOCKED");
                        }
                        else if (desiredAccess & FILE_WRITE_DATA)
                        {
                            if (!(Config.Roles[i].Permissions & WRITE)) denyOp = TRUE;

                            DbgPrint("Role Sid: %ws\n", groupName.Buffer);
                            DbgPrint("Object: %ws\n", realDirectoryPath);

                            if (!denyOp) DbgPrint("Operation: WRITE   - Status: ALLOWED");
                            else DbgPrint("Operation: WRITE   - Status: BLOCKED");
                        }
                        else if (desiredAccess & FILE_EXECUTE)
                        {
                            if (!(Config.Roles[i].Permissions & EXECUTE)) denyOp = TRUE;

                            DbgPrint("Role Sid: %ws\n", groupName.Buffer);
                            DbgPrint("Object: %ws\n", realDirectoryPath);

                            if (!denyOp) DbgPrint("Operation: EXECUTE - Status: ALLOWED");
                            else DbgPrint("Operation: EXECUTE - Status: BLOCKED");
                        }
                    }
                    else if (Data->Iopb->MajorFunction == IRP_MJ_READ)
                    {
                        if (!(Config.Roles[i].Permissions & READ)) denyOp = TRUE;

                        DbgPrint("Role Sid: %ws\n", groupName.Buffer);
                        DbgPrint("Object: %ws\n", realDirectoryPath);

                        if (!denyOp) DbgPrint("Operation: READ    - Status: ALLOWED");
                        else DbgPrint("Operation: READ    - Status: BLOCKED");
                    }
                    else if (Data->Iopb->MajorFunction == IRP_MJ_WRITE)
                    {
                        if (!(Config.Roles[i].Permissions & WRITE)) denyOp = TRUE;

                        DbgPrint("Role Sid: %ws\n", groupName.Buffer);
                        DbgPrint("Object: %ws\n", realDirectoryPath);

                        if (!denyOp) DbgPrint("Operation: WRITE   - Status: ALLOWED");
                        else DbgPrint("Operation: WRITE   - Status: BLOCKED");
                    }

                    break;
                }
            }
        }

        FltReleaseFileNameInformation(nameInfo);
    }

    ExFreePoolWithTag(processName.Buffer, PROCESS_NAME_TAG);
    ExFreePoolWithTag(groupName.Buffer, GROUP_NAME_TAG);

    if (!denyOp)
    {
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
    else
    {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
}

FLT_POSTOP_CALLBACK_STATUS PostOperationCallback(IN OUT PFLT_CALLBACK_DATA Data,
    IN PCFLT_RELATED_OBJECTS FltObjects,
    IN PVOID CompletionContext,
    IN FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Data);

    UNREFERENCED_PARAMETER(FltObjects);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

BOOLEAN IsPrefix(WCHAR* Prefix, WCHAR* FullString)
{
    while (*Prefix && *FullString)
    {
        if (*Prefix != *FullString) return FALSE;
        Prefix++;
        FullString++;
    }
    return (*Prefix == L'\0');
}

BOOLEAN ComparePaths(WCHAR* PNorm, WCHAR* PHard, BOOLEAN PrefixComp)
{
    int slashCnt = 0;

    PNorm += 2;

    while (*PHard != L'\0')
    {
        if (*PHard == L'\\')
        {
            slashCnt++;
            if (slashCnt == 3) break;
        }
        PHard++;
    }

    if (!PrefixComp) return (BOOLEAN)(wcscmp(PNorm, PHard) != 0);
    else return !IsPrefix(PNorm, PHard);
}

NTSTATUS GetProcessImageName(PUNICODE_STRING ProcessImageName)
{
    NTSTATUS status;
    ULONG returnedLength;
    ULONG bufferLength;
    PVOID buffer;
    PUNICODE_STRING imageName;

    if (ZwQueryInformationProcess == NULL)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
        ZwQueryInformationProcess = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);
    }

    status = ZwQueryInformationProcess(NtCurrentProcess(),
        ProcessImageFileName, NULL, 0, &returnedLength);

    if (status != STATUS_INFO_LENGTH_MISMATCH)
    {
        return status;
    }

    bufferLength = returnedLength - sizeof(UNICODE_STRING);
    if (ProcessImageName->MaximumLength < bufferLength)
    {
        ProcessImageName->Length = (USHORT)bufferLength;
        return STATUS_BUFFER_OVERFLOW;
    }

    buffer = ExAllocatePoolWithTag(NonPagedPool, returnedLength, PROCESS_INFO_TAG);
    if (buffer == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQueryInformationProcess(NtCurrentProcess(),
        ProcessImageFileName, buffer,
        returnedLength, &returnedLength);

    if (NT_SUCCESS(status))
    {
        imageName = (PUNICODE_STRING)buffer;
        RtlCopyUnicodeString(ProcessImageName, imageName);
    }

    ExFreePool(buffer);
    return status;
}

NTSTATUS GetUserGroups(PFLT_CALLBACK_DATA Data, PUNICODE_STRING MatchedGroupName)
{
    PEPROCESS requestorProcess = NULL;
    PACCESS_TOKEN token = NULL;
    PTOKEN_GROUPS groups = NULL;
    NTSTATUS status;

    requestorProcess = FltGetRequestorProcess(Data);
    if (requestorProcess == NULL)
    {
        return STATUS_UNSUCCESSFUL;
    }

    token = PsReferencePrimaryToken(requestorProcess);
    if (token == NULL)
    {
        return STATUS_UNSUCCESSFUL;
    }

    status = SeQueryInformationToken(token, TokenGroups, (PVOID*)&groups);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(token);
        return status;
    }

    if (groups->GroupCount >= 3)
    {
        PSID sid = groups->Groups[2].Sid;

        if (RtlValidSid(sid))
        {
            UNICODE_STRING sidString;
            status = RtlConvertSidToUnicodeString(&sidString, sid, TRUE);
            if (NT_SUCCESS(status))
            {
                RtlCopyUnicodeString(MatchedGroupName, &sidString);
                RtlFreeUnicodeString(&sidString);
            }
        }
    }

    ExFreePool(groups);
    ObDereferenceObject(token);

    return STATUS_SUCCESS;
}