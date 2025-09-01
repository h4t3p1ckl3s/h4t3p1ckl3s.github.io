---
title: "Retrieving plaintext Keepass database password in Memory Forensics using Windbg"
description: "A technique I have acquired throughout a local CTF"
categories: ["Writeups"]
tags: ["Digital Forensics"]
date: 2025-08-31
draft: false
cover: /images/posts_cover/windbg.png
math: true
---

# Retrieving plaintext KeePass database password in Memory Forensics using Windbg

## First thought

I have acquired this technique during a local CTF challenge about Memory Forensics. Enjoy reading guys.

At first, I was given 3 files, a process memory dump, a .kdbx file (KeePass password database) and a password-protected zip file. From there, the challenge's flow is gonna be `finding kdbx password -> unlock the zip file`.

Definitely the given minidump is `KeePass.exe` process dump. To prove it, load the minidump into Windbg, a multipurpose debugger for the Microsoft Windows computer operating system, distributed by Microsoft. It can be used to debug user mode applications, device drivers, and the operating system itself in kernel mode. [Wikipedia]([Wikipedia](https://en.wikipedia.org/wiki/WinDbg))

Using `!analyze -v` to have a general overview and detailed technical analysis of the dump file.
![image](https://hackmd.io/_uploads/r12Pp3z5xg.png)

As indicated by the `PROCESS_NAME` field, the dump file originated from the `KeePass.exe` process, which is consistent with the application we were troubleshooting.

Because KeePass is an open source project, we could find more information about it here: 
https://github.com/wrouesnel/keepass

Researching it for a while, I figured out a class that's responsible for storing and protecting **user-entered password** for the KeePass database itself, ensuring it remains encrypted in memory to prevent exposure by malicious software or memory dumping techniques, which is called `ProtectedString`

## ProtectedString
This class is a cornerstone of KeePass's security model, specifically designed to mitigate the risk of in-memory attacks. Unlike a standard .NET `string` object—which is immutable but resides in memory as plain text and can be moved around by the Garbage Collector in an unsecured manner — the `ProtectedString` class provides a secure container.

We only focus about how the password is stored in the memory and how to retreive it, so here are 2 attributes that are related to those.

### `m_pbUtf8` and `m_strPlainText`

```csharp=
private bool m_bIsProtected;
```
So whenever m_bIsProtected = 1 (`IsProtected flag is True`) The **user-entered password** is always stored as encrypted password in the memory. But if it's not (m_bIsProtected = 0), the password is gonna be stored in plaintext.
So here's how you retrieve it.

## Retrieving the password

Use `!dumpheap -type <class>` to get the address for the objects in specified class.

![image](https://hackmd.io/_uploads/BkmlVTfqeg.png)
``` 
!dumpheap -type KeePassLib.Security.ProtectedString
         Address               MT     Size
0000000002dd90e0 00007ffa49031b90       40     
0000000002dd9108 00007ffa49031b90       40     
0000000002f7e500 00007ffa49031b90       40     

Statistics:
              MT    Count    TotalSize Class Name
00007ffa49031b90        3          120 KeePassLib.Security.ProtectedString
Total 3 objects
```
We have 3 objects in total, let's dump every single one to see which objects has been flagged with `m_bIsProtected = true` and which one still stores the plaintext password.

Using `!DumpObj /d <address>` to dump object at specific address including classname and attributes.
```
0:020> !DumpObj /d 0000000002dd90e0
Name:        KeePassLib.Security.ProtectedString
MethodTable: 00007ffa49031b90
EEClass:     00007ffa48786f40
Size:        40(0x28) bytes
File:        E:\KeePass Password Safe 2\KeePass.exe
Fields:
              MT    Field   Offset                 Type VT     Attr            Value Name
00007ffa49031d00  4001383        8 ...y.ProtectedBinary  0 instance 0000000000000000 m_pbUtf8
00007ffafed507a0  4001384       10        System.String  0 instance 0000000002b31420 m_strPlainText
00007ffafed4c638  4001385       1c       System.Boolean  1 instance                0 m_bIsProtected
00007ffafed53368  4001388       18         System.Int32  1 instance               -1 m_nCachedLength
00007ffa49031b90  4001386     2660 ...y.ProtectedString  0   static 0000000002dd90e0 m_psEmpty
00007ffa49031b90  4001387     2668 ...y.ProtectedString  0   static 0000000002dd9108 m_psEmptyEx
0:020> !DumpObj /d 0000000002dd9108
Name:        KeePassLib.Security.ProtectedString
MethodTable: 00007ffa49031b90
EEClass:     00007ffa48786f40
Size:        40(0x28) bytes
File:        E:\KeePass Password Safe 2\KeePass.exe
Fields:
              MT    Field   Offset                 Type VT     Attr            Value Name
00007ffa49031d00  4001383        8 ...y.ProtectedBinary  0 instance 0000000002dd9148 m_pbUtf8
00007ffafed507a0  4001384       10        System.String  0 instance 0000000000000000 m_strPlainText
00007ffafed4c638  4001385       1c       System.Boolean  1 instance                1 m_bIsProtected
00007ffafed53368  4001388       18         System.Int32  1 instance                0 m_nCachedLength
00007ffa49031b90  4001386     2660 ...y.ProtectedString  0   static 0000000002dd90e0 m_psEmpty
00007ffa49031b90  4001387     2668 ...y.ProtectedString  0   static 0000000002dd9108 m_psEmptyEx
0:020> !DumpObj /d 0000000002f7e500
Name:        KeePassLib.Security.ProtectedString
MethodTable: 00007ffa49031b90
EEClass:     00007ffa48786f40
Size:        40(0x28) bytes
File:        E:\KeePass Password Safe 2\KeePass.exe
Fields:
              MT    Field   Offset                 Type VT     Attr            Value Name
00007ffa49031d00  4001383        8 ...y.ProtectedBinary  0 instance 0000000000000000 m_pbUtf8
00007ffafed507a0  4001384       10        System.String  0 instance 0000000002fba5d8 m_strPlainText
00007ffafed4c638  4001385       1c       System.Boolean  1 instance                1 m_bIsProtected
00007ffafed53368  4001388       18         System.Int32  1 instance               25 m_nCachedLength
00007ffa49031b90  4001386     2660 ...y.ProtectedString  0   static 0000000002dd90e0 m_psEmpty
00007ffa49031b90  4001387     2668 ...y.ProtectedString  0   static 0000000002dd9108 m_psEmptyEx
```
As you can see, not all `ProtectedString` instances will directly expose the master password. In the first object (`0x2dd9108`), the password is still safely wrapped inside a `ProtectedBinary` and has never been converted into a managed string, which means its contents remain encrypted in memory. However, in the second object (`0x2f7e500`), we can clearly observe that the `m_strPlainText` field points to a valid `System.String`, while `m_pbUtf8` is already null. This indicates that KeePass has decrypted the protected value and stored it in plaintext within process memory, making it retrievable through WinDbg.

So some of you guys are wondering how could this possible, it's because of a method called `ReadString()`, so what exactly is `ReadString()` ?
>ReadString(): Convert the protected string to a standard string object. Be careful with this function, as the returned string object isn't protected anymore and stored in plain-text in the process memory.

In other words, whenever `ReadString()` (or a similar method) is called inside KeePass, the encrypted buffer is discarded and replaced with a managed string, which then remains in memory until garbage collected. This is exactly the weak point that memory-dumping techniques exploit: even if `m_bIsProtected` is set to true, once plaintext is generated, the protection flag does not change, and the password may still be extracted by inspecting the `System.String` object.

From there, let's dump all the objects at `m_strPlaintext` (after it has been converted into plaintext by `ReadString()`)
![image](https://hackmd.io/_uploads/Bk1LYpGcex.png)
```
!DumpObj /d 0000000002fba5d8
Name:        System.String
MethodTable: 00007ffafed507a0
EEClass:     00007ffafed04868
Size:        76(0x4c) bytes
File:        C:\WINDOWS\Microsoft.Net\assembly\GAC_64\mscorlib\v4.0_4.0.0.0__b77a5c561934e089\mscorlib.dll
String:      first_stage_of_this_chall
Fields:
              MT    Field   Offset                 Type VT     Attr            Value Name
00007ffafed53368  4000283        8         System.Int32  1 instance               25 m_stringLength
00007ffafed51610  4000284        c          System.Char  1 instance               66 m_firstChar
00007ffafed507a0  4000288       e0        System.String  0   shared           static Empty
```
Succesfully retrieved the password, I used it to unlock the .kdbx file
![image](https://hackmd.io/_uploads/B1DRYaM9ge.png)


## Final thought
By digging into `ProtectedString`, we can see how KeePass attempts to protect sensitive data by never keeping the cleartext password in memory longer than necessary. Instead, it stores an encrypted form and only decrypts when explicitly required, such as when `ReadString()` - or other method - is invoked. This design greatly reduces the attack surface, but as we’ve demonstrated, the cleartext can still be recovered in a live debugging session once the method is called and the `m_strPlainText` field is populated.

This highlights an important lesson: memory protection mechanisms are only as strong as the runtime environment allows. Tools like WinDbg or process dump analyzers can bypass these protections if attackers gain sufficient privileges. For defenders, it emphasizes the need to combine application-level security (like `ProtectedString`) with broader system-level protections such as secure OS configuration, anti-debugging measures, and least-privilege principles.

Ultimately, KeePass does a solid job in limiting exposure, but we as researchers (or attackers) must remember that once code execution or memory access is possible, no secret in memory is ever truly safe.

References:
https://github.com/wrouesnel/keepass/blob/master/KeePassLib/Security/ProtectedString.cs

https://fossies.org/dox/KeePass-2.59-Source/classKeePassLib_1_1Security_1_1ProtectedString.html
