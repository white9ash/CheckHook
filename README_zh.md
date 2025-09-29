# CheckHook

[English](README.md) | 中文

一个用于检测Windows动态链接库(DLL)函数Hook的安全分析工具。该工具能够扫描加载的模块，检测是否有函数被EDR进行Hook操作。

## 概述

CheckHook 是一个轻量级的Windows安全工具，用于检测系统中关键DLL函数是否被Hook。

## 使用方法
构建项目并双击运行。

## 原理

CheckHook 通过访问进程 PEB (Process Environment Block) 结构遍历所有已加载的 DLL 模块，解析每个模块的 PE 格式导出表获取所有导出函数地址，然后检查函数入口点的字节码是否为 JMP 指令（0xE9），如果跳转目标超出原始模块地址范围则判定为被 Hook。该工具主要检测基于 JMP 指令的简单 Hook。

## 检测的DLL列表
工具会检测以下关键系统DLL，可根据需求自行添加其他DLL。
"ws2_32.dll", "wininet.dll", "winhttp.dll", "urlmon.dll", "iphlpapi.dll"
"advapi32.dll", "crypt32.dll", "bcrypt.dll", "cryptsvc.dll", "schannel.dll"
"psapi.dll", "netapi32.dll", "srvcli.dll", "sechost.dll", "setupapi.dll"
"dbghelp.dll", "tlhelp32.dll"
"user32.dll", "gdi32.dll", "shell32.dll", "comctl32.dll"
"msvcrt.dll", "ucrtbase.dll", "msvcp140.dll"
"kernel32.dll", "ntdll.dll", "ole32.dll", "rpcrt4.dll"

## 截图
<p align="center">
  <img src="img/screenshot.png" width="250">
</p>

## 许可证

本项目采用MIT许可证。详细信息请参阅LICENSE文件。

## 免责声明

⚠️ **重要提醒**: 
- 本工具仅用于教育和合法的安全研究目的
- 请勿用于恶意目的或未经授权的系统
- 使用本工具的风险由用户自行承担
- 作者不对因使用本工具造成的任何损失负责

---

**注意**: 该工具在Windows 10/11 x64系统上测试通过。不保证在其他系统版本上的兼容性。

