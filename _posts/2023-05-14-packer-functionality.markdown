---
layout: single
title:  "Packer Functionality"
# date:   2024-06-01 16:44:45 -0500
categories: "Malware-Analysis"
toc: true
author_profile: true
classes: wide
---

# Software Packers
In this post we'll delve into what packers are and how malware developers use their functionality to their benefit.

## What is a Packer? 
A **packer**, in its simplest form, can be thought of as a self-extracting archive. Packers were initially used to compress executable files because they allowed for smaller file sizes while still being easy to use. A packed file remains executable, so end users do not have to manually unpack the file before being able to execute it. However, as a consequence of the packing process, the original contents get obfuscated and are not observable statically. While packers are not inherently malicious, they are attractive to malware developers as they can help avoid detection. Packers have since grown in sophistication with added features to better defend against analysis and reverse engineering. As a result packers go by many different names which reflect their specialized functionality. This includes:
- **Crypters** - encrypt the original target file. 
- **Protectors** - are designed to prevent reverse engineering and tampering of programs. They can accomplish this by both packing and encrypting the target file. Modern protectors opt for code virtualization, where a randomized instruction set is used and is unique to each protected binary. 

While no definitions for these are set in stone, I consider both crypters and protectors to be *types* of packers in that they:
1. all carry a transformed version (compressed, encrypted, or virtualized) of the original binary and
2. recover or perform the same execution of the original binary.

## Applications
Packers are not inherently malicious and are legitimately used by companies to protect their software against piracy. Legitimate packers include [UPX](https://upx.github.io/) and [Themida](https://www.oreans.com/Themida.php). 

On the other hand, malicious packers main purpose is antivirus evasion. More advanced malicious packers go beyond avoiding static detection by also stealthily executing its payload; usually via memory injection techniques. 

Understanding if a file was packed with a legitimate packer is simple. Static analysis tools such as Detect-it-Easy, that can identify what packer was used. Malicious packers will usually not self identify, but it is usually possible to identify if a sample is packed based on a binary's entropy and strings. 

## Packing Process
At a high level, the traditional process of packing a given binary is pretty straightforward. Given a binary, a packer will encrypt and/or compress the contents of the target file. The packer then generates a *stub*, which is another executable file that contains the unpacking routine and acts as a loader for the packed contents. The resulting packed file points to the stub (a.k.a. envelope) as the entry point and also contains packed data as shown below:

![Packing Process](/assets/images/packing_process.png)

### Execution Process for a Packed File

1\. Depending how the file was packed, the stub will:
- decompress the packed payload, which originally was the target file.
- and/or decrypt the encrypted data within itself   

2\. Now that the original binary has been recovered it can be executed in memory. There are two main ways to do this:

2.1 Run the target file in the memoryspace of the current process. This is the approach taken by most legitimate processes. 
- This is usually done by reserving a section that has enough empty space in memory to place the decrypted/decompressed portion into it. This kinds of sections have a raw size of 0, but have a big virtual size. 

2.2	Inject and execute the original binary in another process's memory space. API such as `VirtualAlloc` and `WriteProcessMemory` can be used to inject the original binary into a remote process's memory space and `CreateRemoteThread` can be used to trigger execution. 

**How does the Stub know where the encrypted/compressed content is located?**
A common way this is done is by utilizing start and end markers. If the content is encrypted there will be a key or a key generation function inside the stub as well. The decryption key or key generation function may be useful in writing static unpackers. ([Guide](https://www.gdatasoftware.com/blog/2019/01/31413-unpack-lpdinch-malware)) Other common placement of contents in the sub:
- end of the file (overlay) - or a fixed offset from the end.
- last section - this is useful as the size of this section can be easily expanded without it affecting other sections 
- PE Resources
- .NET resources
- huge base64 string containing the encrypted data.

### Binary Padding
Binary padding is used by packers to change small portions of the file randomly. This may be adding random data to the packed file. This inevitably changes the hash value of the packed file even if the stub and input file are the same. This method counters blacklisting by antivirus products.

### Unique Stub Generation (USG)
The packer implements mechanisms to create a unique stub for every packed file.  This is a polymorphic packer, although whether or not this is truly polymorphic is still contested. 
- This kind of packer, has a raw stub or stub pieces that it can modify to create many different possible variants. 
- This may be accomplished by shuffling instructions where order does not matter, or adding "junk instructions" in random places. 
- When compared to *binary padding*, USG also evades antivirus pattern detection. 

## Misconceptions about Packers

**Packers do not inject into compiled binaries.**
In other words, packers do not make it so that only parts of the target file are encrypted/compressed. Doing so is overly complicated for a packer. This is because making changes to a compiled binary requires detailed knowledge of the internal structures of that binary.
* Doing so is possible, but most malware does not do this for the purposes of evasion. Leaving parts unencrtypted or uncompressed makes evasion less likely to succeed. 
* An exception is viruses that may do this, but for other purposes.

**Scantime Crypters are not Packers**
* Scantime crypters are actually "builders" for malware droppers.  

**The following are not Polymorphic**
* Usage of Binary Padding
* When a packer carries hundreds or thousands of stubs that are used to pick one randomly from. This would actually be a oligomorphic crypter, because there are only a few predefined forms.   

## References:
- MalwareAnalysisForHedgehogs: [Malware Theory - Packers](https://youtu.be/ESLEf66EzDk)
