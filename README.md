# Some useful utilities for STAB debug information parsing

Some useful utilities STAB debuginfo related utilities that may be helpful in reversing.  

Missing dependencies, or get `ModuleNotFoundError`? Install them with `python3 -m pip`  

# ELF to split STAB section

Supports reading `.stab`, `.stabstr`, and `.mdebug` section.  
`.mdebug` section will be converted to the `.stab` and `.stabstr` specification.  
Limitations:  
* 32-bit support only

Usage:  
```bash
python3 /path/to/elf_to_split_stab.py /path/to/input/file.elf /path/to/output/file.stab /path/to/output/file.stabstr
```

# Split STAB section to ELF

Supports reading `.stab`, and `.stabstr` pre-split files.  
Limitations:  
* 32-bit support only

Usage:  
```bash
python3 /path/to/split_stab_to_elf.py /path/to/input/file.stab /path/to/input/file.stabstr /path/to/output/file.elf
```

# STABS debug info to JSON

A patch to `prdbg.c` from GNU Binutils that will output the information in JSON format.  
Some functionality (like C++ data types) are not implemented properly.  

# JSON to the scripting format of an industry-leading disassembler

`json2pcode.py` converts the output of the above "STABS debug info to JSON" to the scripting format of an industry-leading disassembler.  
Known missing/incomplete features:  
* C++ types  
* Local variables  
* 64-bit support  

Due to independency issues, you need to run the generated script twice.  

# See also

gdb-stabs documentation: https://sourceware.org/gdb/current/onlinedocs/stabs.html  
StabsParser pull request for Ghidra: https://github.com/NationalSecurityAgency/ghidra/pull/1460  
objdump documentation from Binutils: https://sourceware.org/binutils/docs/binutils/objdump.html  

# License

For `prdbg.c`, GPL v3 (or at your option any later version).  
For everything else, MIT license, see `LICENSE` file for more information  
