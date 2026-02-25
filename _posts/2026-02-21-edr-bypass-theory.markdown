---
layout: single
title:  "EDR Evasion Theory on Windows"
excerpt: "Some notes on EDR detection mechanisms on Windows and EDR Evasion Theory."
categories: "Malware-Analysis"
toc: true
author_profile: true
classes: wide
---

# EDR Detection Mechanisms on Windows

## EDR Static Detection
Static detection surfaces are few and relatively easy to evade detection. EDRs may leverage PE Imports, Strings, and Code Patterns as detection vectors. Importantly, high-entropy data is also suspicious. This is why simply encrypting payloads will not suffice. 

### Evading Static Detection
The overall goal is to minimize the footprint of your payload's strings and code while maintaining low entropy. I see this with more advanced malware, which will catter real plaintext data among its payload. Additional techniques may be to encode bytes to correspond to ASCII or words. 

LLVMs such as [YANSOllvm](https://github.com/emc2314/YANSOllvm) can do this for us with the added benefit of complicating reverse engineering. In summary, static analysis and detection necessitates:
1. Low-entropy obfuscation and
2. process injection for payload execution. 

## EDR Behavioral Detection

### Common Behavioral Detection Strategies
The following are common approaches to behavioral detection:

**(1)** API Hooking (basically standard)
- Inspecting of argument data for suspicious API.
- Logging of API call activity.

**(2)** Periodical scanning of running threads.
- YARA rules may be applied to their memory.
- Their call stack may be analyzed.

**(3)** Condition-Based Analysis: EDRs conduct additional analysis based certain conditions being met, such as:
- RWX memory regions.
- RX memory regions not backed by a file on disk. (Private executable memory region is a red flag!)
- Sleeping/suspended threads.
- Loaded image in memory, but not linked in the PEB.

### EDR Telemetry Sources
- Malware databases used for static detection.
- Telemetry from EDR DLL injected into processes.
- Telemetry from OS:
	- Kernel callbacks and minifilters
	- ETW-Ti
	- AMSI/ETW
- Telemetry from memory.
	- memory scanners
	- call stack analysis 
- Telemetry from sandbox.
- Telemetry from local network events and gateway network traffic.

**Sandbox**

Are used to observe initial behavior, but can only analyze for a small amount of time before impacting user experience. 
- Most malware attempts to evade sandbox by using sleep, however many sandboxes just skip this; sleep obfuscation may be a way to bypass.

**AMSI**

AMSI is the "Anti-Malware Scan Interface" which is used to inspect plaintext code running on Windows; this also includes some .NET assemblies. Windows uses the `AmsiScanBuffer` API to analyze content in-memory before execution. 
- Many bypasses for this exist.

**Kernel Callbacks**

Kernel callbacks such as those listed below can be used by EDRs and AVs to register callbacks from the operating system at the Kernel level. In other words, the Windows kernel will execute the "callback" function registered with a function like one these below:
- `PsSetCreateProcessNotifyRoutine` - process creation/exit
- `PsSetCreateThreadNotifyRoutine` - thread monitoring
- `PsSetLoadImageNotifyRoutine`  <-- does `LdrRegisterDllNotification` (used by LB4) bypass this??
	- A: No, `LdrRegisterDllNotification` fires in **user space only for the current process**.
- `ObRegisterCallbacks` - handle access
- `CmRegisterCallbackEx` -  registry changes
- `FltRegisterFilter` - file operations
The callback function must also live at the kernel level and are usually found in a driver belonging to the EDR/AV protecting the system. **NOTE:** EDRs and AVs still need to **hook APIs** because there are not kernel callbacks available for all syscalls. (Technically, callbacks can be registered for other syscalls using `PsAltSystemCallHandlers`; however, this is undocumented.) 

**Minifilters**

A **File System Minifilter Driver** is a kernel-mode driver that plugs into the Kernel's **Filter Manager** (`fltmgr.sys`) and can be used to inspect, intercept, or even modify filesystem I/O request (IRPs - I/O Request Packets). 
- **EDRs** rely on minifilters because it enables direct visibility into filesystem I/O for monitoring. This enables features such as:
	- On-Access file scanning
	- Monitoring of file creation/modification
	- Tamper protection - minifilters can deny attempts to delete or modify EDR binaries or configuration. 
	- Anti-Ransomware - some EDRs use journaling minifilters to maintain copies or original files for rollback in ransomware is detected.
	- Minifilters are more robust than API hooking which can be bypassed at user-mode level.
	- Use of minifilters does add a performance overhead that must be considered by EDR developers.
- **Malware** can abuse minifilters for stealth by hiding its files/directories as well as (less stealthy) blocking AV.

**ETW**

ETW is "Event Tracing for Windows" which is a kernel-level logging mechanism for system and application events. 
- ETW collects telemetry from OS components, applications, and security sub-systems. 
- User mode providers, including security relevant ones, use `EtwEventWrite` for logging, which can be bypassed with hooks or patching.
	- This does NOT bypass ETW, instead it blinds user-mode event providers that rely on it.
	- Kernel mode providers such as ETW-TI are unaffected as well as EDRs that subscribe directly with the kernel using `NtTraceControl`

**ETW-TI**

ETW-TI is the Windows Threat Intelligence provider, which is a kernel-mode provider for ETW and can be used to monitor for malicious behavior without hooks or drivers. Malware would need Kernel access to tamper with ETW-TI.
- Only PPL-AntiMalware processes can register to read ETW-Ti logs. 

Further ETW-TI Reading:
- [Interesting ETW-TI writeup](https://fluxsec.red/full-spectrum-event-tracing-for-windows-detection-in-the-kernel-against-rootkits). 
- [Reading ETW-TI in Rust](https://fluxsec.red/event-tracing-for-windows-threat-intelligence-rust-consumer). 

**Memory Scan and Call Stack Analysis**

- Memory Scan is a static analysis of a target process's memory region. This includes memory permissions and flags.
- Calls stack analysis inspects a call stack of a function to determine where it was called from. 

**Memory Scanners**

Memory scanners look for anomalies in memory any analyze dynamically allocated memory. Analyze memory dumps taken at runtime, which can leverage YARA rules to ID known malicious patterns. Memory dumps can be triggered as a result of:
- process events (e.g. thread creation) 
- suspicious memory such as:
	- RWX memory
	- executable memory not backed by a file on disk
Memory scanners also investigate:
- Hooks and memory patches
- PE header reconstruction
- Unsigned loaded modules
- Known malicious patterns (e.g. using YARA)
- Analyze call stack
- Analyze executable memory

**Network Analysis**

External networking tools and hardware can be used as well as many Windows sub-systems can be used for network monitoring and analysis, such as:
- Kernel network stack callbacks
- ETW network providers

# EDR Evasion Theory
There are 3 main avenues to EDR evasion:
1. Operate under the detection threshold (e.g. LOLbins)
2. Block Telemetry (e.g. unhooking, killing EDR Agent/Sensor)
3. Poison Telemetry (e.g. Stack spoofing)

Successful red teams adjust payloads and approach based on the unique target environment. This includes identifying telemetry sources and patterns that trigger detection events in that environment. They may be exceptions in either direction (more or less sensitive detection), based on the unique environment needs.

## **Operating Under the Detection Threshold**
- EDRs assign a score to monitored events and if a threshold is reached an alert is triggered.
- The goal is to limit the generation of suspicious telemetry to AV/EDR information source and can be accomplished through:
	- Domain Fronting - is a technique that uses different domain names in different communication layers of an HTTPS connection to connect to a different target domain than is discernable to monitoring.
	- HTTPS traffic shaping
	- LOLBins and trusted binaries
	- DLL sideloading and DLL proxying
	- Use of uncommon APIs, Dynamic API resolution, and indirect syscalls.

## **Blocking Telemetry**
Can by accomplished by:
- unhooking
- patching logging functions like AMSI and EtwEventWrite
- killing EDR Agent/Sensor

## **Poisoning Telemetry**
- The goal is to conceal malicious actions.
- This can be done by identifying the information your process controls which EDRs may rely on. This includes
	- This includes the stack since it is our memory space, which means we can obfuscate any suspicious call we want to make by spoofing the stack.