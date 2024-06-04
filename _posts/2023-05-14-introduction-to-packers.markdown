---
layout: single
title:  "Introduction to Packers"
# date:   2024-06-01 16:44:45 -0500
categories: "Malware-Analysis"
toc: true
author_profile: true
classes: wide
---

# Software Packers
In this post we'll delve into what packers are and how malware developers use their functionality to their benefit.

## What is a Packer? 
A **packer**, in its simplest form, can be thought of as a self-extracting archive. Packers were initially used to compress executable files because they allowed for smaller file sizes while still being easy to use. A packed file remains executable, so end users do not have to manually unpack the file before being able to execute it. However, as a consequence of the packing process, the original contents get obfuscated and are not observable statically. While packers are not inherently malicious, they are attractive to malware developers as they can help avoid detection. Packers have since grown in sophistication with added features to better defend against analysis and reverse engineering. As a result, packers go by many different names, which reflect their specialized functionality. This includes:
- **Crypters** - encrypt the original target file. 
- **Protectors** - are designed to prevent reverse engineering and tampering of programs. They can accomplish this by both packing and encrypting the target file. Modern protectors opt for code virtualization, where a randomized instruction set is used and is unique to each protected binary. 

While done of these definitions are set in stone, I consider both crypters and protectors to be *types* of packers in that they:
1. all carry a transformed version (compressed, encrypted, or virtualized) of the original binary and
2. recover or perform the same execution of the original binary.

## Applications
Packers are not inherently malicious and are legitimately used by companies to protect their software against piracy. Legitimate packers include [UPX](https://upx.github.io/) and [Themida](https://www.oreans.com/Themida.php). 

On the other hand, malicious packers main purpose is to evade antivirus. More advanced malicious packers go beyond avoiding static detection by also stealthily executing its payload; usually via memory injection techniques. 

Understanding if a file was packed with a legitimate packer is simple. Static analysis tools such as Detect-it-Easy, that can identify what packer was used. Malicious packers will usually not self-identify, but it is usually possible to identify if a sample is packed based on a binary's entropy and strings. 

## Packing Process
At a high level, the traditional process of packing a given binary is pretty straightforward. Given a binary, a packer will encrypt and/or compress the contents of the target file. The packer then generates a *stub*, which is another executable file that contains the unpacking routine and acts as a loader for the packed contents. If the content is encrypted, the stub will also contain a key or a key generation function as well. The resulting packed file points to the stub (a.k.a. envelope) as the entry point and also contains packed data as shown below:

![Packing Process](/assets/images/packing_process.png)

Common placement for the packed data may be the PE resources section or at a fixed offset from the end of the file. There will always be alternative methods for storing the packed data, such as storing it as a large base64 encoded strings.
### Execution Process for a Packed File

1\. Depending how the file was packed, the stub will:
- decompress the packed payload, which originally was the target file
- and/or decrypt the encrypted data within itself   

2\. Now that the original binary has been recovered, it can be executed in memory. There are two main ways to do this:

2.1 Execute the target file in the memoryspace of the current process. This is a common approach used by legitimate processes. This is usually done by reserving a section that has enough empty space in memory to place the decrypted/decompressed portion into it. This kind of sections have a raw size of 0, but have a big virtual size. 

2.2	Inject and execute the original binary in another process's memory space. API such as `VirtualAlloc` and `WriteProcessMemory` can be used to inject the original binary into a remote process's memory space and `CreateRemoteThread` can be used to trigger execution. 

## Evasion Techniques

### Binary Padding
Binary padding is used by packers to change small portions of the file randomly. This may be adding random data to the packed file. This inevitably changes the hash value of the packed file despite the stub and input file remaining the same. This technique is not as effective as generating a unique stub since signatures can still be written against the stub, but still counters signature based detection.

### Generating a Unique Stub
To prevent from signatures being written to detect the code patterns of a stub, packers will leverage "junk code" which are instructions that do not change the execution of the program. They are added to the stub to bypass static detection and to make efforts to develop detection rules more difficult. Additionally, the order in which instructions occur may be shuffled where order does not matter. A packer that implements these mechanisms, produces unique files even if the same target file is provided and may be considered a polymorphic packer.   

## References
- MalwareAnalysisForHedgehogs: [Malware Theory - Packers](https://youtu.be/ESLEf66EzDk)
