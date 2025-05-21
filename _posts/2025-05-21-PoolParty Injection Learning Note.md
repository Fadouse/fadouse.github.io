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

## 第一种注入技术 **复写workerfactory start routine**

workerfactory是用于维护线程池的高效运行，但并不会直接执行线程。<br>

WorkerFactory中包含控制线程的入口点(start routine),
换言之我们只需要控制start rountine就可以执行我们的代码。

但是直接将start routine指向我们的shellcode是不现实的。
因为在workerfactory创建时start routine的值是常量，不可更改的。

既然start routine是一段指针，如果我们向指针指向的内存空间中分配和写入我们的shellcode。
这样我们不就可以成功执行我们的代码了吗？

### 如何获取 start routine 指针？

在内核函数api中，我们发现 ' NtQueryInformationWorkerFactory ' 这个函数可以获取当前workerfactory的信息
```c++
NtQueryInformationWorkerFactory(
    _In_ HANDLE WorkerFactoryHandle,
    _In_ ULONG WorkerFactoryInformationClass,
    _Out_writes_bytes_(WorkerFactoryInformationLength) PVOID WorkerFactoryInformation,
    _In_ ULONG WorkerFactoryInformationLength,
    _Out_opt_ PULONG ReturnLength
);
```
并且其中就包含 WorkerFactoryInformation (start routine) 的指针值。

随后我们即可复写在start routine处的内存空间，使windows机制自己执行我们的恶意shellcode。

### 如何在更改后立即执行？

我们并不确定我们的shellcode何事执行，这是因为我们只是将Shellcode‘加入’到线程池中，并没有立刻执行代码。

> 持续更新中....