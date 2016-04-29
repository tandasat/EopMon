// Copyright (c) 2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements EopMon functions.

#include "eopmon.h"
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "../HyperPlatform/HyperPlatform/kernel_stl.h"
#include <vector>
#include <algorithm>

extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

// PLACE TO IMPROVE:
// EopMon handles processes with any of those names as system processes. It
// means that if adversaries can bypass EopMon by using other processes'
// tokens. It may be an idea to check every process's token and see if that
// is associated with SYSTEM privileges.
static const char* kEopmonpSystemProcessNames[] = {
    "Idle",        "System",       "smss.exe",  "csrss.exe",
    "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe",
};

////////////////////////////////////////////////////////////////////////////////
//
// types
//

// A parameter of EopmonpTerminateProcessWorkerRoutine
struct EopmonWorkQueueItem {
  WORK_QUEUE_ITEM work_item;
  HANDLE dodgy_pid;
  const char* system_process_name;
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS
    EopmonpForEachProcess(_In_ bool (*callback_routine)(HANDLE pid, void*),
                          _In_opt_ void* context);

_IRQL_requires_max_(PASSIVE_LEVEL) static bool EopmonpCheckProcessToken(
    _In_ HANDLE pid, _In_opt_ void* context);

_IRQL_requires_max_(PASSIVE_LEVEL) static bool EopmonpInitTokenOffset(
    _In_ PEPROCESS process, _In_ PACCESS_TOKEN token);

static WORKER_THREAD_ROUTINE EopmonpTerminateProcessWorkerRoutine;

_IRQL_requires_max_(PASSIVE_LEVEL) static PUNICODE_STRING
    EopmonpGetProcessPathByHandle(_In_ HANDLE process_handle);

static PACCESS_TOKEN EopmonpGetProcessToken(_In_ PEPROCESS process);

static PACCESS_TOKEN EopmonpGetProceesTokenFromAddress(_In_ ULONG_PTR address);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, EopmonInitializaion)
#pragma alloc_text(INIT, EopmonpForEachProcess)
#pragma alloc_text(INIT, EopmonpCheckProcessToken)
#pragma alloc_text(INIT, EopmonpInitTokenOffset)
#pragma alloc_text(PAGE, EopmonTermination)
#pragma alloc_text(PAGE, EopmonpTerminateProcessWorkerRoutine)
#pragma alloc_text(PAGE, EopmonpGetProcessPathByHandle)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

// Sets of SYSTEM token and owner process name. Usage of those tokens are
// monitored.
static std::vector<std::pair<PACCESS_TOKEN, const char*>>*
    g_eopmonp_system_process_tokens;

// An array of system processes. They are allowed to use the above tokens, as
// those processes are owners of them.
static std::vector<HANDLE>* g_eopmonp_system_process_ids;

// An offset to the Token field in EPROCESS
static ULONG g_eopmonp_offset_to_token;

// An array to remember what processes are queued for termination. Without this,
// the same process is going to be queue hundreds of times before it is actually
// terminated.
static HANDLE g_eopmonp_processes_being_killed[8];

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Initializes EopMon
_Use_decl_annotations_ NTSTATUS EopmonInitializaion() {
  PAGED_CODE();
  // HYPERPLATFORM_COMMON_DBG_BREAK();

  g_eopmonp_system_process_tokens =
      new std::vector<std::pair<PACCESS_TOKEN, const char*>>();
  g_eopmonp_system_process_ids = new std::vector<HANDLE>();

  auto status = EopmonpForEachProcess(EopmonpCheckProcessToken, nullptr);
  if (!NT_SUCCESS(status) || !g_eopmonp_offset_to_token) {
    delete g_eopmonp_system_process_ids;
    delete g_eopmonp_system_process_tokens;
    return status;
  }

  return status;
}

// Executes \a callback_routine for all processes.
_Use_decl_annotations_ static NTSTATUS EopmonpForEachProcess(
    bool (*callback_routine)(HANDLE pid, void*), void* context) {
  PAGED_CODE();

  // For ZwQuerySystemInformation
  enum SystemInformationClass {
    kSystemProcessInformation = 5,
  };

  // For ZwQuerySystemInformation
  struct SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    UCHAR Reserved1[48];
    PVOID Reserved2[3];
    HANDLE UniqueProcessId;
    PVOID Reserved3;
    ULONG HandleCount;
    UCHAR Reserved4[4];
    PVOID Reserved5[11];
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved6[6];
  };

  // prototype
  NTSTATUS NTAPI ZwQuerySystemInformation(
      _In_ SystemInformationClass SystemInformationClass,
      _Inout_ PVOID SystemInformation, _In_ ULONG SystemInformationLength,
      _Out_opt_ PULONG ReturnLength);

  // Get a necessary size of buffer
  ULONG_PTR dummy = 0;
  ULONG return_length = 0;
  auto status = ZwQuerySystemInformation(kSystemProcessInformation, &dummy,
                                         sizeof(dummy), &return_length);
  if (NT_SUCCESS(status) || return_length <= sizeof(dummy)) {
    return status;
  }

  // Allocate s bit larger buffer to handle new processes in case
  const auto allocation_size =
      return_length + sizeof(SYSTEM_PROCESS_INFORMATION) * 10;
  const auto system_info =
      reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(ExAllocatePoolWithTag(
          PagedPool, allocation_size, kHyperPlatformCommonPoolTag));
  if (!system_info) {
    return STATUS_MEMORY_NOT_ALLOCATED;
  }

  status = ZwQuerySystemInformation(kSystemProcessInformation, system_info,
                                    allocation_size, &return_length);
  if (!NT_SUCCESS(status)) {
    ExFreePoolWithTag(system_info, kHyperPlatformCommonPoolTag);
    return status;
  }

  // For each process
  for (auto current = system_info; current->NextEntryOffset;
       current = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(
           reinterpret_cast<ULONG_PTR>(current) + current->NextEntryOffset)) {
    if (!callback_routine(current->UniqueProcessId, context)) {
      // Exit when a callback returned false, but not as failure
      break;
    }
  }

  ExFreePoolWithTag(system_info, kHyperPlatformCommonPoolTag);
  return status;
}

// Remembers a SYSTEM token and its owner name if applicable
_Use_decl_annotations_ static bool EopmonpCheckProcessToken(HANDLE pid,
                                                            void* context) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(context);

  extern const char* NTAPI PsGetProcessImageFileName(_In_ PEPROCESS Process);

  // Get EPROCESS
  PEPROCESS process = nullptr;
  auto status = PsLookupProcessByProcessId(pid, &process);
  if (!NT_SUCCESS(status)) {
    return true;
  }

  // Test if a process name of this pid matches with any of known system
  // processes.
  const auto process_name = PsGetProcessImageFileName(process);
  for (auto system_process_name : kEopmonpSystemProcessNames) {
    if (!RtlEqualMemory(process_name, system_process_name,
                        strlen(system_process_name))) {
      continue;
    }

    // System process found
    const auto token = PsReferencePrimaryToken(process);

    // Initialize g_eopmonp_offset_to_token if not yet
    if (!g_eopmonp_offset_to_token && !EopmonpInitTokenOffset(process, token)) {
      PsDereferencePrimaryToken(token);
      ObfDereferenceObject(process);
      return false;  // error. cannot continue
    }

    // PLACE TO IMPROVE:
    // EopMon updates a list of system processes' tokens and IDs, while some
    // of them like csrss.exe and winlogon.exe can be terminated and re-launched
    // when an use logout and logon to the system. One solution would be
    // installing process notification callback and maintain the latest system
    // process list.
    g_eopmonp_system_process_tokens->emplace_back(token, system_process_name);
    g_eopmonp_system_process_ids->push_back(pid);
    HYPERPLATFORM_LOG_INFO("System Token %p with PID=%Iu %s", token, pid,
                           system_process_name);

    PsDereferencePrimaryToken(token);
  }

  ObfDereferenceObject(process);
  return true;
}

// Search EPROCESS::Token offset from a pair of EPROCESS and token
_Use_decl_annotations_ static bool EopmonpInitTokenOffset(PEPROCESS process,
                                                          PACCESS_TOKEN token) {
  PAGED_CODE();

  // Search up to a 0x80 pointers size
  for (auto offset = 0ul; offset < sizeof(void*) * 0x80;
       offset += sizeof(void*)) {
    const auto address = reinterpret_cast<ULONG_PTR>(process) + offset;
    const auto possible_token = EopmonpGetProceesTokenFromAddress(address);
    if (possible_token == token) {
      g_eopmonp_offset_to_token = offset;
      HYPERPLATFORM_LOG_INFO("EPROCESS::Token offset = %x", offset);
      return true;
    }
  }

  HYPERPLATFORM_LOG_ERROR("Token could not found within an expected range.");
  return false;
}

// Terminates EopMon
_Use_decl_annotations_ void EopmonTermination() {
  PAGED_CODE();

  delete g_eopmonp_system_process_ids;
  delete g_eopmonp_system_process_tokens;
}

// Checks if the current process's token matchs with one of system tokens. If so
// queue work item to terminate the process.
_Use_decl_annotations_ void EopmonCheckCurrentProcessToken() {
  // PLACE TO IMPROVE:
  // This check is performed only when CR3 is changed. While it seems frequent
  // enough to detect an escalated process before it does anything meaningful,
  // there is a window allowing exploit running with SYSTEM privileges a bit
  // while. To fill this gap, it may be an idea to perform this check more
  // often. For example, setting 0xCC at a SYSTENTER handler, handling #BP in
  // the hypervisor and calling this function will be more frequent (although
  // it may slow down the system more).

  // If IRQL is higher than DISPATCH_LEVEL we cannot do anything anyway
  if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
    return;
  }

  const auto& system_tokens = *g_eopmonp_system_process_tokens;
  const auto& system_process_ids = *g_eopmonp_system_process_ids;
  auto& being_killed_pids = g_eopmonp_processes_being_killed;

  // nt!KiSwapProcess
  //  pid1 = attaching process
  //  pid2 = attached process
  // nt!SwapContext
  //  pid1 = new process
  //  pid2 = new process
  const auto process = PsGetCurrentProcess();
  const auto pid1 = PsGetCurrentProcessId();
  const auto pid2 = PsGetProcessId(process);
  UNREFERENCED_PARAMETER(pid1);

  // Is it a known, safe process?
  for (auto system_pid : system_process_ids) {
    if (pid2 == system_pid) {
      // Yes, it is. This process is ok.
      return;
    }
  }

  // It its token one of those of system processes?
  const char* system_process_name = nullptr;
  const auto token = EopmonpGetProcessToken(process);
  for (auto& system_token : system_tokens) {
    if (token == system_token.first) {
      system_process_name = system_token.second;
      break;
    }
  }
  if (!system_process_name) {
    // No, it is not. This process is ok.
    return;
  }

  // Is this PID already queued for termination?
  for (auto pid_being_killed : being_killed_pids) {
    if (pid2 == pid_being_killed) {
      // Yes, it is. Nothing to do.
      return;
    }
  }

  // We have found a process using the same system token as one of system
  // processes. Let us terminate the process.

  // PLACE TO IMPROVE:
  // It would be better off issueing a bug check rather than killing the process
  // because the system has already been exploited and could be somewhat
  // unstable condition. For example, the HalDispatchTable might have already
  // been modified, and the author found that running Necurs's exploit
  // (CVE-2015-0057) multiple times led a bug check. For this reason, it worth
  // considering dieing spectacularly rather than giving (potentially) false
  // sense of security.

  // HYPERPLATFORM_COMMON_DBG_BREAK();

  // Remember this PID as one already queued for termination
  for (auto& pid_being_killed : being_killed_pids) {
    if (!pid_being_killed) {
      pid_being_killed = pid2;
      break;
    }
  }

  // Allocate and queue a work queue item for delayed termination
  const auto context = reinterpret_cast<EopmonWorkQueueItem*>(
      ExAllocatePoolWithTag(NonPagedPool, sizeof(EopmonWorkQueueItem),
                            kHyperPlatformCommonPoolTag));
  if (!context) {
    HYPERPLATFORM_LOG_WARN_SAFE("Memory allocation failure.");
    return;
  }
  ExInitializeWorkItem(&context->work_item,
                       EopmonpTerminateProcessWorkerRoutine, context);
  context->dodgy_pid = pid2;
  context->system_process_name = system_process_name;
  ExQueueWorkItem(&context->work_item, CriticalWorkQueue);
  HYPERPLATFORM_LOG_DEBUG_SAFE(
      "Process %Iu with a stolen token %p from %s has been queued for "
      "termination.",
      pid2, token, system_process_name);
}

// Terminates a given process and wait for its completion.
_Use_decl_annotations_ static void EopmonpTerminateProcessWorkerRoutine(
    void* parameter) {
  PAGED_CODE();

  // HYPERPLATFORM_COMMON_DBG_BREAK();

  const auto context = reinterpret_cast<EopmonWorkQueueItem*>(parameter);
  const auto dodgy_pid = context->dodgy_pid;
  const auto system_process_name = context->system_process_name;

  // Open a process handle
  OBJECT_ATTRIBUTES oa = {};
  InitializeObjectAttributes(
      &oa, nullptr, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);
  CLIENT_ID client_id = {dodgy_pid, 0};
  HANDLE process_handle = nullptr;
  auto status =
      ZwOpenProcess(&process_handle, PROCESS_ALL_ACCESS, &oa, &client_id);
  HYPERPLATFORM_LOG_DEBUG("Process %Iu is being processed (status = %08x).",
                          dodgy_pid, status);
  if (!NT_SUCCESS(status)) {
    goto exit;
  }

  // Terminate it and wait
  status = ZwTerminateProcess(process_handle, 0);
  HYPERPLATFORM_LOG_DEBUG("Process %Iu is being terminated (status = %08x).",
                          dodgy_pid, status);
  if (status == STATUS_PROCESS_IS_TERMINATING) {
    goto exit_with_close;
  }
  NT_VERIFY(NT_SUCCESS(status));

  status = ZwWaitForSingleObject(process_handle, FALSE, nullptr);
  NT_VERIFY(NT_SUCCESS(status));

  // log stuff
  const auto process_path = EopmonpGetProcessPathByHandle(process_handle);
  if (!process_path) {
    HYPERPLATFORM_LOG_INFO(
        "Process %Iu with a stolen token %s has been killed.", dodgy_pid,
        system_process_name);
    goto exit_with_close;
  }

  PEPROCESS process = nullptr;
  status = PsLookupProcessByProcessId(dodgy_pid, &process);
  if (!NT_SUCCESS(status)) {
    HYPERPLATFORM_LOG_INFO(
        "Process %Iu with a stolen token from %s has been killed. Image= %wZ",
        dodgy_pid, system_process_name, process_path);
    ExFreePoolWithTag(process_path, kHyperPlatformCommonPoolTag);
    goto exit_with_close;
  }

  const auto token = PsReferencePrimaryToken(process);
  HYPERPLATFORM_LOG_INFO(
      "Process %Iu with a stolen token %p from %s has been killed. Image= %wZ",
      dodgy_pid, token, system_process_name, process_path);

  PsDereferencePrimaryToken(token);
  ObfDereferenceObject(process);
  ExFreePoolWithTag(process_path, kHyperPlatformCommonPoolTag);

exit_with_close:;
  ZwClose(process_handle);

  // Delete this PID from ones being marked as already queued
  for (auto& pid_being_killed : g_eopmonp_processes_being_killed) {
    if (pid_being_killed == dodgy_pid) {
      pid_being_killed = nullptr;
    }
  }

exit:;
  ExFreePoolWithTag(context, kHyperPlatformCommonPoolTag);
}

// Gets an image path of the process from its handle. A caller must free a
// returned path with ExFreePoolWithTag(..., kHyperPlatformCommonPoolTag).
_Use_decl_annotations_ static PUNICODE_STRING EopmonpGetProcessPathByHandle(
    HANDLE process_handle) {
  PAGED_CODE();

  extern NTSTATUS NTAPI ZwQueryInformationProcess(
      _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass,
      _Out_ PVOID ProcessInformation, _In_ ULONG ProcessInformationLength,
      _Out_opt_ PULONG ReturnLength);

  // Get a necessary size of buffer
  ULONG_PTR dummy = 0;
  ULONG return_length = 0;
  auto status =
      ZwQueryInformationProcess(process_handle, ProcessImageFileName, &dummy,
                                sizeof(dummy), &return_length);
  if (NT_SUCCESS(status) || return_length <= sizeof(dummy)) {
    return nullptr;
  }

  const auto image_path =
      reinterpret_cast<PUNICODE_STRING>(ExAllocatePoolWithTag(
          PagedPool, return_length, kHyperPlatformCommonPoolTag));
  if (!image_path) {
    return nullptr;
  }

  // Get an image path
  status = ZwQueryInformationProcess(process_handle, ProcessImageFileName,
                                     image_path, return_length, &return_length);
  if (!NT_SUCCESS(status)) {
    return nullptr;
  }
  return image_path;
}

// Gets an address of the \a process
_Use_decl_annotations_ static PACCESS_TOKEN EopmonpGetProcessToken(
    PEPROCESS process) {
  const auto address =
      reinterpret_cast<ULONG_PTR>(process) + g_eopmonp_offset_to_token;
  return EopmonpGetProceesTokenFromAddress(address);
}

// Get an address of a token from a value of EPROCESS::Token, which does not
// directly point to the token address.
_Use_decl_annotations_ static PACCESS_TOKEN EopmonpGetProceesTokenFromAddress(
    ULONG_PTR address) {
  // To get an address, the lowest N bits where N is a size of a RefCnt field
  // needs to be masked.
  const auto value = *reinterpret_cast<ULONG_PTR*>(address);
  if (IsX64()) {
    // kd> dt nt!_EX_FAST_REF
    //   + 0x000 Object           : Ptr64 Void
    //   + 0x000 RefCnt : Pos 0, 4 Bits
    //   + 0x000 Value : Uint8B
    return reinterpret_cast<PACCESS_TOKEN>(value &
                                           (static_cast<ULONG_PTR>(~0xf)));
  } else {
    // kd>  dt nt!_EX_FAST_REF
    //   + 0x000 Object           : Ptr32 Void
    //   + 0x000 RefCnt : Pos 0, 3 Bits
    //   + 0x000 Value : Uint4B
    return reinterpret_cast<PACCESS_TOKEN>(value &
                                           (static_cast<ULONG_PTR>(~7)));
  }
}

}  // extern "C"
