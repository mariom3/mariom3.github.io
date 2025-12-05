---
layout: single
title:  "Rust Binary Analysis 101 - Part I"
# date:   2024-06-01 16:44:45 -0500
categories: "Malware-Analysis"
toc: true
author_profile: true
classes: wide
---

# Background
It takes a rare breed of human to be thrilled to reverse engineer a complex Rust program. Unfortunately... or fortunately? I am not one of them. My first encounter with a Rust binary was unintentional and exciting at first; a Russian APT malware sample. What kind of malware RE wouldn't be intrigued by that?

<!-- Needless to say my excitement took a hit when the IDA decompiler spit this out: -->
It didn't take long after loading the program into IDA for me to realize it was going to be more of a headache than I had anticipated... 

![Rust Malware Decompilation](/assets/images/rust-analysis/decomp.png)

When your decompiler spits out something like this, you inevitably feel like you need to make a run for it while your sanity is still intact. Or perhaps take inspiration from Homer Simpson and hide from your problems?

<img src="/assets/images/rust-analysis/simpsons.gif" alt="Simpsons GIF" style="display: block;margin: auto;width: 70%;">

As with many complex problems, it's best to start with the basics. So, I decided to write a basic Rust program; and in true CTF-fashion, I took the opportunity to hide a flag in there as a simple challenge for other Malware REs. This post is part 1 of 2 to document my findings about the intricacies of analyzing Rust binaries and provide a practical way for learners to approach the topic:
- Part I: In this post we'll focus on developing a basic Rust program to get more familiar with the language itself, but complex enough to serve as an exercise that is also interesting to reverse engineer. 
- Part II: This will focus on the intricacies of analyzing Rust binaries as well as comparing how IDA vs Ghidra handle Rust binaries. 

For those diving deeper, this BlackHat talk is also a great watch: 
- [Project 0xA11C: Deoxidizing the Rust Malware Ecosystem](https://www.youtube.com/watch?v=cMIhIARmNfU)

## A Small Challenge
The program developed in the following sections is intended to be an easier exercise for seasoned REs to statically analyze (introducing dynamic analysis would make it far too easy). The program is also intended to bring to focus the differences Rust itself brings to commonly encountered malicious code patterns. 
- I'd encourage you to review the source code, as well as, try to write a similar program yourself. It's always interesting to see what a compiler will generate from your code.
- If you'd like to give it a try, there are 2 binaries (password is `infected`):
    1. You can find the main binary here: [basic_rust_re.zip](/assets/basic_rust_re.zip)
    - HASH: fe9cac217b0b72c8e6cabd447000acd6c7ecba43f47cbe242f127722480a78af
    2. A simpler version of the same code made for beginners: [basic_rust_re_beginner.zip](/assets/basic_rust_re_beginner.zip)
    - HASH: da8e52df67fdf440c645bf6bc5a54f05dc798f1b7bae4c59a38a677f5da3701f

**The solution is available in [Part 2]({% post_url 2025-12-04-rust-binary-analysis2%})!**

---

# Writing a Basic Rust Program
The task is simple: Write a program that prompts the user for a password and print if the user provides the correct password or not. 

1 - The first task is have the program take user input:

```rust
use std::io::{self, Write};

fn main() {
    println!("Enter the password:"); 
    io::stdout().flush().unwrap();   // Ensure the prompt is shown immediately

    let mut input_password = String::new();
    io::stdin()
        .read_line(&mut input_password)
        .expect("Failed to read line");
    let input_password = input_password.trim();
}
```
2 - Next we need to take that user-supplied input and compare it to the password. So we've got to make up a password to compare with the user input. _(To avoid spoiling the challenge, I won't say what I selected for the password here.)_ I chose to use an XOR-gencrypted version of the password to up the spice 🌶️ level just a bit. Programmatically, this means we need to:
- encrypt the user-supplied input the same way and with the same XOR key used for the password before comparing them.
- define an `xor_crypt` routine (shown in the next section). 
- compare the hard-coded encrypted password with the encrypted user input.

```rust
let input_bytes: &[u8] = input_password.as_bytes();
let input_crypt = xor_crypt(input_bytes, xor_key);
    
let password: &[u8] = &[0xFF, 0xFF, ...];
if password == input_crypt {
    println!("Welcome! Password correct ^_^");
} else {
    println!("Sorry, keep trying!")
}
```

3 - To ensure the user can read the program's response, we add another prompt for user input to prevent the program from exiting.

```rust
println!("Press enter to exit.");
io::stdout().flush().unwrap(); 
let mut input = String::new();

io::stdin()
    .read_line(&mut input)
    .expect("Failed to read line");
```

## Adding Obfuscation
At this point, this would be way too easy for any RE. So let's make it interesting by adding commonly seen obfuscation patterns such as XOR-encrypted strings. 

Since we have an `xor_crypt` routine (shown below), let's use it to encrypt any strings we've introduced. Because the Rust compiler produces statically linked binaries, encrypting strings will help hide our code a bit more. 

```rust 
fn xor_crypt(input_bytes: &[u8], key: u8) -> Vec<u8> {
    let mut result = Vec::with_capacity(input_bytes.len());
    for &byte in input_bytes {
        result.push(byte ^ key);
    }
    result
}
```

We can XOR-encrypt strings with an XOR key of our choosing and hard-code the resulting bytes as an array in our code. Then, we can use the `xor_crypt` routine with the corresponding XOR key to recover the plaintext at runtime before printing it. So `println!("Enter the password:");` becomes:

```rust
let welcome_msg: &[u8] = &[0x7c, 0x57, 0x4d, 0x5c, 0x4b, 0x19, 0x4d, 0x51, 0x5c, 0x19, 0x49, 0x58, 0x4a, 0x4a, 0x4e, 0x56, 0x4b, 0x5d, 0x03];
let welcome_msg = xor_crypt(welcome_msg, 0x39);
let welcome_msg = String::from_utf8(welcome_msg).unwrap();
println!("{welcome_msg}");
```

## Adding Anti-Debug 
Since this is intended to be a static analysis challenge, we can make this more interesting by adding an anti-debug measure. However, before doing so we need to address the trust issues Rust has with developers accessing program memory. 

### Let's talk about Rust's Trust Issues
Rust wants developers to admit that they usually don't know what they're doing before the compiler allows anyone to programmatically access memory. To do this, Rust provides the `unsafe` keyword that developers must use to encapsulate this kind of code. It seems that, by default, Rust will only compile code that it can prove to be safe. For this reason, it will refuse to compile code that works directly with pointers or inline assembly. 

### Dynamically Setting the XOR Key
Of course, there are simpler anti-debug techniques, but I wanted to introduce a bit of a challenge for anyone attempting to debug this. Instead of quitting if a debugger is detected, I wanted to dynamically set the XOR key used to decode the password. For this, I opted to use the `NtGlobalFlag` from the PEB, which is `0x00` if not being debugged; otherwise the the following flags are set:
- FLG_HEAP_ENABLE_TAIL_CHECK (0x10)
- FLG_HEAP_ENABLE_FREE_CHECK (0x20)
- FLG_HEAP_VALIDATE_PARAMETERS (0x40)

**NOTE:** The `NtGlobalFlag` is not the most robust option as it is only set when the process starts. So if a debugger is attached after the process is created, it will read `0x00`! 

1 - We need to define a structure to reference the PEB and retrieve the `NtGlobalFlag`. To avoid RE-ing undocumented PEB structures, we can define a PEB structure that only contains the `NtGlobalFlag`:

```rust
struct PEB {
    // Padding to reach the offset where NtGlobalFlag is located (in x64 processes)
    _reserved1: [u8; 0xBC],  
    NtGlobalFlag: u32,       // Define size of NtGlobalFlag 
}
```

2 - Now, the `unsafe` keyword is needed when defining the code that retrieves the PEB. To keep things simple we are only supporting x64. In this case, we need to read the GS segment register, which requires us to use inline assembly in Rust. To do this, we define a function `__readgsqword` that implements that functionality. Next, we define another function the uses `__readgsqword` to read the PEB and return the `NtGlobalFlag`:

```rust
use core::arch::asm;
use winapi::shared::minwindef::DWORD;
use winapi::shared::basetsd::DWORD64;

unsafe fn __readgsqword(offset: DWORD) -> DWORD64 {
    let out: u64;
    asm!(
        "mov {}, gs:[{:e}]",
        lateout(reg) out,
        in(reg) offset,
        options(nostack, pure, readonly),
    );
    out
}

unsafe fn get_ntGlobalFlag() -> u32 {
    let peb_offset = __readgsqword(0x60) as *const u64;
    let rf_peb: *const PEB = peb_offset as *const PEB;
    let peb = &*rf_peb;

    (*peb).NtGlobalFlag
}
```

3 - Now, we can read the `NtGlobalFlag` using the `get_ntGlobalFlag` routine we wrote. We can call this after we get the user's input and use it to influence the XOR key used to encrypt the input before comparing it to the password. Of course, since we're using an unsafe function, we must encapsulate its use in an `unsafe {}` block. 

```rust
unsafe {
    // Get the last byte of the NtGlobalFlag by & with 0xFF
    let mut ntGlobalFlag: u8 = (get_ntGlobalFlag() & 0xFF) as u8;
    // +1 in hopes of adding a bit more complexity.
    ntGlobalFlag += 1;
    // NtGlobalFlag is expected to be 0x00 if not being debugged. 
    let xor_key = ntGlobalFlag + <XOR_KEY - 1>;
    let input_crypt = xor_crypt(input_bytes, xor_key);

    let password: &[u8] = &[0xFF, 0xFF, ...];

    if password == input_crypt {
        ...
    }
    ...
}
```

## Completed Program 
Done! The complete source for the program is provided below. Stay tuned for Part II, which includes an analysis walk through!

```rust
// Compiler notes
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

// Dependencies
use core::arch::asm;
use std::io::{self, Write};
use winapi::shared::minwindef::DWORD;
use winapi::shared::basetsd::DWORD64;

struct PEB {
    _reserved1: [u8; 0xBC],  // Padding to reach the offset where NtGlobalFlag is located
    NtGlobalFlag: u32,       // Define size of NtGlobalFlag 
}

// Inline assembly required to read the PEB
unsafe fn __readgsqword(offset: DWORD) -> DWORD64 {
    let out: u64;
    asm!(
        "mov {}, gs:[{:e}]",
        lateout(reg) out,
        in(reg) offset,
        options(nostack, pure, readonly),
    );
    out
}

unsafe fn get_ntGlobalFlag() -> u32 {
    let peb_offset = __readgsqword(0x60) as *const u64;
    let rf_peb: *const PEB = peb_offset as *const PEB;
    let peb = &*rf_peb;

    (*peb).NtGlobalFlag
}

fn xor_crypt(input_bytes: &[u8], key: u8) -> Vec<u8> {
    let mut result = Vec::with_capacity(input_bytes.len());
    for &byte in input_bytes {
        result.push(byte ^ key);
    }
    result
}

fn main() {
    
    // Get user input
    let welcome_msg: &[u8] = &[0x7c, 0x57, 0x4d, 0x5c, 0x4b, 0x19, 0x4d, 0x51, 0x5c, 0x19, 0x49, 0x58, 0x4a, 0x4a, 0x4e, 0x56, 0x4b, 0x5d, 0x03];
    let welcome_msg = xor_crypt(welcome_msg, 0x39);
    let welcome_msg = String::from_utf8(welcome_msg).unwrap();
    println!("{welcome_msg}");
    // println!("Enter the password:");
    io::stdout().flush().unwrap(); // Ensure the prompt is shown immediately

    let mut input_password = String::new();
    io::stdin()
        .read_line(&mut input_password)
        .expect("Failed to read line");
    let input_password = input_password.trim();
    let input_bytes: &[u8] = input_password.as_bytes();

    unsafe {
        let mut ntGlobalFlag: u8 = (get_ntGlobalFlag() & 0xFF) as u8;
        ntGlobalFlag += 1;
        let xor_key = ntGlobalFlag + <XOR_KEY - 1>; // <-- REDACTED
        let input_crypt = xor_crypt(input_bytes, xor_key);
    
        let password: &[u8] = &[0xFF, ...]; // <-- REDACTED

        if password == input_crypt {
            let success_msg: &[u8] = &[0x6e, 0x5c, 0x55, 0x5a, 0x56, 0x54, 0x5c, 0x18, 0x19, 0x69, 0x58, 0x4a, 0x4a, 0x4e, 0x56, 0x4b, 0x5d, 0x19, 0x5a, 0x56, 0x4b, 0x4b, 0x5c, 0x5a, 0x4d, 0x19, 0x67, 0x66, 0x67];
            let success_msg = xor_crypt(success_msg, 0x39);
            let success_msg = String::from_utf8(success_msg).unwrap();
            println!("{success_msg}");
            // println!("Welcome! Password correct ^_^");
        } else {
            let fail_msg: &[u8] = &[0x6a, 0x56, 0x4b, 0x4b, 0x40, 0x15, 0x19, 0x52, 0x5c, 0x5c, 0x49, 0x19, 0x4d, 0x4b, 0x40, 0x50, 0x57, 0x5e, 0x18];
            let fail_msg = xor_crypt(fail_msg, 0x39);
            let fail_msg = String::from_utf8(fail_msg).unwrap();
            println!("{fail_msg}");
            // println!("Sorry, keep trying!")
        }
    }

    let exit_msg: &[u8] = &[0x69, 0x4b, 0x5c, 0x4a, 0x4a, 0x19, 0x5c, 0x57, 0x4d, 0x5c, 0x4b, 0x19, 0x4d, 0x56, 0x19, 0x5c, 0x41, 0x50, 0x4d, 0x17];
    let exit_msg = xor_crypt(exit_msg, 0x39);
    let exit_msg = String::from_utf8(exit_msg).unwrap();
    println!("{exit_msg}");
    // println!("Press enter to exit.");
    io::stdout().flush().unwrap(); 
    let mut input = String::new();

    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");
}
```


# Helpful Resources
- Great BlackHat Talk: [Project 0xA11C: Deoxidizing the Rust Malware Ecosystem](https://www.youtube.com/watch?v=cMIhIARmNfU)
