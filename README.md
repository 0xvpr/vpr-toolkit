# VPR's Toolkit
A collection of various tools & utilities related to security research,  
reverse engineering, and malware analysis.

### How to use
```bash
curl -LSso- https://raw.githubusercontent.com/0xvpr/vpr-toolkit/main/vpr-toolkit | python3 - -p ./toolkit -i vpr-omega-zero
```

### Table of Contents
- [Templates](#templates)
- [Binary Injection and Modification](#binary-injection-and-modification)
- [Utility](#utility)
- [Formatting](#formatting)

## Templates
|Name|Description|Link|
|----|-----------|----|
|shell-shock|A C++20 compatible header only library capable of creating position independent shellcode.|https://github.com/0xvpr/vpr-shell-shock|
|deviate|C99/C++20 Header only library for dependency free function hooking in windows.|https://github.com/0xvpr/vpr-deviate|

## Binary Injection and Modification
|Name|Description|Link|
|----|-----------|----|
|omega-zero|A program to remove section-header information from 32/64 bit ELF and PE32 executables.|https://github.com/0xvpr/vpr-omega-zero|
|pidjeon|A command line payload injector for 32 & 64 bit Windows applications.|https://github.com/0xvpr/vpr-pidjeon|
|midas|A program to modify datetime information of a given file(s).|https://github.com/0xvpr/vpr-midas|

## Utility
|Name|Description|Link|
|----|-----------|----|
|overwatch|A command line utility for executing a specified command when a file(s) is/are modified.|https://github.com/0xvpr/vpr-overwatch|

## Formatting
|Name|Description|Link|
|----|-----------|----|
|extract|A utility program to rip sections of Position Independent Code (PIC) from 32/64-bit COFF objects and ELF64 Relocatable objects and output them to a desired file.|https://github.com/0xvpr/vpr-extract|
|bin2fmt|A utility program to convert binary data to a formatted string of the user's choice.|https://github.com/0xvpr/vpr-bin2fmt|
