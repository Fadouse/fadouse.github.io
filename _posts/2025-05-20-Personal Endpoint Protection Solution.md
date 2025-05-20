---
title: Personal Endpoint Protection Solution
date: 2025-05-20
categories: [security]
tags: [security, EDR, EPP]
---

## 目录

- [引言](#引言)
- [威胁现状分析](#威胁现状分析)
- [传统EPP/EDR的局限](#传统eppedr的局限)
- [初步尝试](#初步尝试)
- [Elastic + SentinelOne 组合实践](#elastic--sentinelone-组合实践)
- [总结与展望](#总结与展望)

---

## 引言

有人可能认为，在当下的网络环境中，只要保持良好的上网习惯，甚至不装杀毒软件就足够了。但实际上，情况并非如此。如今的网络威胁与2000年左右病毒作者猖獗、特征明显的时代已经大不相同。现在的病毒更加隐蔽，威胁等级更高，越来越多的APT（高级持续性威胁）组织针对各国和地区发起攻击，各种0day漏洞层出不穷。

## 威胁现状分析

即使我作为一名高中生，也可以制作出能够绕过卡巴斯基、360、火绒等常见个人杀软检测的“白加黑”远控木马（后续会单独开博客讲解）。这意味着，即使只是普通上网，也有可能中毒。这些在野样本往往无法被传统杀软及时拦截（如病毒特征库无记录、0day行为未被收录、利用系统合法工具攻击等），传统EPP（Endpoint Protection Platform，终端防护平台）软件可能无法完全防护和记录。

此时，NGAV（Next Generation Antivirus，下一代杀毒软件）的优势就体现出来了。NGAV放弃了传统特征库和行为库，转而使用静态AI和动态AI引擎作为检测和防护的基础，例如 Cylance、Deep Instinct、SentinelOne 等。

同时，EDR/XDR（Endpoint/Extended Detection and Response，终端/扩展检测与响应）的概念也被引入。客户端上的 Agent 会安装 EDR 传感器，采集注册表、文件、进程、注入、DLL 加载、DNS、网络等所有行为，并在后台建立进程间的关系链。当 EPP 预警或云端 AI 检测到可疑行为时，可以呈现完整的入侵和感染记录，保证系统无需重装即可彻底清理感染。同时，EDR 还能通过 IOC（威胁情报）和自定义规则自动响应，阻断大范围感染，最大程度降低损失。

因此，我认为，在当前环境下，个人用户只是因为“没有利用价值”才暂时未被攻击。一旦你有被利用价值（如 Lumma Stealer 等通过 Web 调用窃取各类登录令牌）或被误攻击时，传统杀软已无法做到及时、完整的防护。

## 传统EPP/EDR的局限

我已经初步尝试过各大 EDR 产品（SentinelOne、KNEXT（Kaspersky）、Deep Instinct、ESET Protect Advanced、Bitdefender），并发现大部分“传统 EDR 产品”并不能有效地在威胁阶段初期拦截威胁，只是单纯地记录行为并在后台生成告警或者指标，甚至客户端都没有任何提醒。

这对于个人或者无 24h 安全团队的公司并不有利，很有可能导致如勒索/窃密木马等软件已经运行并达成其入侵目的（详细参考 [2024 MITRE Enterprise 测试](https://evals.mitre.org/results/enterprise?view=cohort&evaluation=er6&result_type=PROTECTION&scenarios=4)），此时 EDR 已经无力回天（无回滚或者 VSS 备份的 EDR 产品），导致文件无法恢复，窃密成功，造成个人/企业财产威胁。

因此，我们需要 EPP 和 EDR 都强大的防护解决方案，不应仅在后台记录，而应该即时拦截并自动回滚威胁对系统的操作，尽可能减少威胁对系统的影响。但我发现貌似单个解决方案都无法彻底满足以上要求。

## 初步尝试

于是，我开始尝试多个解决方案部署在一台终端上。最开始采用的组合是 Deep Instinct 和 SentinelOne（一个 EPP 非常强，一个 EDR 行业 leader），但发现这两者都会设置 r3hook，导致系统不稳定或崩溃，甚至 Deep Instinct 会替代系统的核心 DLL，如下图所示：

![Deep Instinct DLL 替换示意](images/deepinstinct_dlls.png)

在被这套搭配折磨了一个月后，我卸载了 Deep Instinct（毕竟 SentinelOne 搭配 star 规则还是能顶的）。

## Elastic + SentinelOne 组合实践

后续，在卡饭坛友的推荐下，我尝试了 Elastic 配合 SentinelOne。Elastic 的技术实现完全基于 Windows 原生 API，ETWTI 和内核栈回调作为检测点，完全不设置系统、内核钩子，所以 Elastic 的兼容性非常好，基本不会与任何杀软和软件产生兼容问题。

Elastic 作为最初专注于 AI 搜索技术的公司，其静态机器学习能力非常强大，能够与 Deep Instinct、CrowdStrike 等顶尖厂商媲美。相比 Deep Instinct，Elastic 的覆盖面更广，不仅具备出色的 EPP 能力，在 EPP 拦截后还能通过完整的内核栈回调检测，进一步还原攻击者的具体手法和 API 调用（即便是 syscall 也有可能被识别）。这也是 Elastic 相较于其他 EDR/EPP 软件的独特优势。

SentinelOne 作为老牌 EDR 厂商，在多次 MITRE 测试中可见性覆盖率前三，甚至在 2024 年达到 100% 可见性。S1 除了强大的 EDR 溯源能力，还提供了独一无二的回滚能力，可以完全回滚威胁进程对系统造成的任何影响，甚至包括直接修改硬盘。

目前，我在家庭环境下三台 Windows 设备部署了 Elastic 和 SentinelOne 的组合，并在**实体机**双击测试卡饭论坛中的样本。在近一月的测试中，对各种威胁的防护率/可见性达到 100%（包括一个[传统 EPP 都无法拦截的样本](https://bbs.kafan.cn/thread-2281596-1-1.html)），并且对任何可见威胁都可以进行完全的溯源和修复（甚至最开始 S1 误报了 ES，给我三天前安装的 ES 全部回滚了，包括驱动）。达到这种性能的同时，花费和对终端的性能影响也在可接受范围内。

## 总结与展望

我将会继续使用这套设置，如有任何问题，会尽快在博客中发布更新。