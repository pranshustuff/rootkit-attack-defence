# rootkit-attack-defence
Learning Project making versions of rootkits and rootkit detection 

## V1 
### Attack
Using Ftrace to redirect pointer for getdents64 to my version. And removing daemon PID from /proc

### Defense
It reads the first bytes of getdents64, looks for an injected JMP/CALL or indirect jump in the function prologue, and flags the target if it points into a loadable kernel module

## V2
### Defense
Uses eBPF kprobes on getdents64 to capture returned directory entries, parse numeric PIDs from the buffer, compare them to a trusted /proc PID list, and alert when active PIDs are missing.
