# GhDB (The Ghidra Debugger)

This project is meant to provide a thin connecting layer between Ghidra and LLDB.

Features include:
    
* Breakpoints set in LLDB show up as bookmarks in Ghidra
* When a breakpoint is hit, Ghidra is navigated to its address

Features on the way:
   
* Breakpoints show up in a custom Ghidra GUI
* Custom Ghidra GUI components to step the debugger

## Usage

Run `install.sh` once. 

Then every time run the script `GhDBServer.java` from Ghidra. 

Once in lldb, prefix command you want to send to Ghidra with "gh". Currently supported command are:

* `b -> ghb`
* `br -> ghbr`
* `breakpoint -> ghbreakpoint`
* `n -> ghn`
* `s -> ghs`
