# GhiDB (The Ghidra Debugger)

This project is meant to provide a thin connecting layer between Ghidra and LLDB. It's currently basically just a PoC.

Features include:
    
* Breakpoints set in LLDB show up as bookmarks in Ghidra
* When a breakpoint is hit, Ghidra is navigated to its address

Features on the way:
   
* Breakpoints show up in a custom Ghidra GUI
* Custom Ghidra GUI components to step the debugger

## Usage

Run `install.sh` once. 

Then every time you want to sync the debugger with Ghidra, run the script `GhiDBServer.java` from Ghidra and then run the command `ghstart` in LLDB.

NOTE: When running `ghstart`, the image you are debugging should already be loaded, i.e. a common pattern might be:

1. `b main`
2. `r`
3. `ghstart`

Once in lldb, prefix breakpoint commands you want to send to Ghidra with "gh". Currently supported command are:

* `b -> ghb`
* `br -> ghbr`
* `breakpoint -> ghbreakpoint`
