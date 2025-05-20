---
title: Windows Backdoor&Reflectiveloader Analysis
date: 2025-05-20
categories: [reverse, malware analysis]
tags: [analysis, reverse, malware]
---

[本样本来自卡饭论坛(Kafan)](https://bbs.kafan.cn/thread-2281596-1-1.html)

## 样本行为&逆向

1. **命令行注入分支**  
   ```cpp
   v5 = strstr(GetCommandLineA(), "-proc ");
   if ( v5 ) {
       DWORD pid = sub_170122D18(v5 + 6);
       HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, pid);
       WaitForSingleObject(h, INFINITE);
       CloseHandle(h);
       return 0;
   }
    ````

* 如果启动参数包含 `-proc <PID>`，程序会附加到指定进程并挂起自身，直到目标进程退出后再终止。

2. **环境指纹与反调试初始化**

   ```cpp
   int seed = unknown_libname_146(0) ^ ~(GetTickCount() * GetCurrentProcessId());
   srand(seed);
   sub_17006DB54();
   sub_17006E194();
   sub_17006D8B8();
   sub_17003E4DC();
   ```

   * 利用当前时间、PID 及“未知库名”生成随机种子，随后调用一系列无意义命名函数完成内存/API 解析等“垃圾初始化”。

3. **持久化目录构造**

   ```cpp
   __int128 *cfg = sub_170064F18();
   ```

   * 通过 `SHGetKnownFolderPath` 获取 `%APPDATA%\boiii`，在该目录下创建或读取配置数据，并注册退出回调以便清理。

4. **第一阶段载荷解密与校验**

   ```cpp
   _QWORD *ctr = sub_170069AC0(v62);
   if ( ctr[2] ) sub_170006848(&Src);
   normalize_backslashes(ctr);
   sub_170006A0C(v62);
   if ( !sub_1700CB778(&Src) ) throw runtime_error("首次启动需要联网");
   ```

   * 调用 `sub_170069AC0` 解密内嵌 payload 容器，替换路径分隔符，擦除临时缓冲，并强制首次联网校验。

5. **进程检查**

   ```cpp
   bool ok1 = sub_1700CB3B0("BlackOps3.exe");
   bool ok2 = sub_1700CB3B0("BlackOps3_UnrankedDedicatedServer.exe");
   if ( !ok1 && !ok2 ) throw runtime_error("未找到合法的游戏可执行");
   ```

   * 确保本地存在合法的游戏可执行文件，否则终止。

6. **更新信息下载与完整性校验**

   ```cpp
   sub_170075B6C(a1, a2);
   sub_170076844(a1, v36, a2);
   ```

   * 向硬编码 C2 `https://bo3.ezz.lol/boiii/` 分阶段下载更新描述和签名信息，使用 `sub_17000A8A8`、`sub_170010438` 等函数多次解包与混淆，并对比本地预期值进行签名校验。

7. **第二阶段载荷解包与验证**

   ```cpp
   sub_17000FE98(&Src, stage2_ptr, stage2_len);
   if ( !sub_1700CB7DC(&Src, v24) )
       throw runtime_error("第二阶段载荷校验失败");
   sub_170006A0C(v36);
   sub_170025EDC(v24);
   ```

   * 使用 `sub_17000FE98` 解包第二阶段二进制，调用 `sub_1700CB7DC` 检查完整性，清理临时缓冲。

8. **反射加载并执行最终 payload**

   ```cpp
   auto payload_entry = (int(*)())sub_17006DA64(payload_buffer);
   return payload_entry();
   ```
    
   * 将验证通过的 PE 映像通过 `sub_17006DA64` 反射加载到内存，获取入口函数指针并直接调用，完成恶意代码的执行。

---

## 总结 & MITRE ATT&CK 矩阵

- 本次分析的样本程序先利用反调试与容器解密进行环境准备并联网校验，随后分阶段下载、解包并在内存中反射加载最终 payload 以实现无痕执行。
![MITRE ATT&CK](images/2025-5-20_mitre_layer_2.svg)

---

## IOC 情报

- bo3.ezz.lol
- https://bo3.ezz/boiii/
- https://bo3.ezz/boiii.json
- D5C923CF806BC0F7639B4DE6DB27CE837D32623129E38C82F1A9421540BD5712



