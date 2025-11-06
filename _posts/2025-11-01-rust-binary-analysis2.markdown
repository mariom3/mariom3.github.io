---
layout: single
title:  "Rust Binary Analyis 101 - Part 2"
# date:   2024-06-01 16:44:45 -0500
categories: "Malware-Analysis"
toc: true
author_profile: true
classes: wide
---

# Background
Text

## The Small Challange
The program developed in the following sections is intended to be an easier exercise for a seasoned REs to statically analyze (itroducing dynamic analysis would make it far too easy). The program is also intended to bring to focus the differences Rust itself brings to commonly encoutnered malicious code patterns. 
- I'd encourage you to review the source code as well as try to write a similar program yourself. Its always interesting to see what a compiler will generate from your code.
- If you'd like to give it a try, there are 2 binaries:
    1. You can find the main binary here: [LINK](https://github.com)
    2. A simpler binary made for beginners is available here: [LINK](https://github.com)


# Rust Binary Analysis
## Comparing IDA 9.1 vs Ghidra 11.3
## Rust Optimizations
### Compiling User Defined Functions
### Unintended Consequences
### Rust LOVES SSE Instructions
## Anti-Analysis
## Password Recovery
  

# Helpful Resources
- Great BlackHat Talk on the Rust Malware Ecosystem: [Rust Malware Ecosystem](https://www.youtube.com/watch?v=cMIhIARmNfU)
