#!/usr/bin/env python3
#
# detect_proc_hiding.py
#
# Defensive prototype: sample getdents64 results via eBPF (BCC) and compare to /proc
#
# Run as root in a test VM: sudo python3 detect_proc_hiding.py
#

from bcc import BPF
from ctypes import Structure, c_uint, c_int, c_ulonglong, c_char
import ctypes
import time
import os
import re
import threading

# max bytes to copy from the user buffer (adjust for safety)
MAX_COPY = 1024

# BPF program
bpf_text = r"""
#include <uapi/linux/ptrace.h>

#define MAX_COPY %d

struct data_t {
    u32 pid;
    s32 ret;
    u32 size;
    char buf[MAX_COPY];
};

BPF_HASH(dirp_map, u64, u64); // key: tid, value: dirp pointer
BPF_PERF_OUTPUT(events);

int kprobe__x64_sys_getdents64(struct pt_regs *ctx, unsigned int fd, void *dirp, unsigned int count) {
    u64 tid = bpf_get_current_pid_tgid();
    // store dirp per tid
    dirp_map.update(&tid, (u64*)&dirp);
    return 0;
}

int kretprobe__x64_sys_getdents64(struct pt_regs *ctx) {
    u64 tid = bpf_get_current_pid_tgid();
    u64 *pdirp = dirp_map.lookup(&tid);
    if (!pdirp)
        return 0;

    void *dirp = (void *)(*pdirp);
    dirp_map.delete(&tid);

    int ret = PT_REGS_RC(ctx);
    if (ret <= 0)
        return 0;

    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ret = ret;

    // only copy up to MAX_COPY bytes
    u32 to_copy = ret;
    if (to_copy > MAX_COPY) to_copy = MAX_COPY;
    data.size = to_copy;

    // safe read from user memory
    int err = bpf_probe_read_user(&data.buf, to_copy, dirp);
    if (err)
        return 0;

    events.perf_submit(ctx, &data, sizeof(struct data_t));
    return 0;
}
""" % (MAX_COPY,)

# Create BPF
b = BPF(text=bpf_text)

# Data structure matching struct data_t in C
class Data(ctypes.Structure):
    _fields_ = [
        ("pid", c_uint),
        ("ret", c_int),
        ("size", c_uint),
        ("buf", c_char * MAX_COPY)
    ]

# parse dirent64 entries from a bytes buffer
# struct linux_dirent64 {
#   ino64 d_ino;
#   off64_t d_off;
#   unsigned short d_reclen;
#   unsigned char d_type;
#   char d_name[];
# };
def parse_dirents(buf_bytes, length):
    i = 0
    pids = set()
    while i + 19 < length:  # minimal size (approx)
        # d_ino: 8 bytes, d_off: 8 bytes, d_reclen: 2 bytes, d_type:1 byte
        if i + 19 > length:
            break
        # reclen is at offset 16 (8 + 8)
        reclen = int.from_bytes(buf_bytes[i+16:i+18], 'little')
        if reclen <= 0 or i + reclen > length:
            break
        # name starts at offset 19 (16+2+1)
        name_off = i + 19
        # name length is reclen - (19 - current base), but safe to locate null
        end = buf_bytes.find(b'\x00', name_off)
        if end == -1 or end > i + reclen:
            # fallback: try to interpret until reclen end
            name = buf_bytes[name_off:i+reclen].split(b'\x00',1)[0].decode(errors='ignore')
        else:
            name = buf_bytes[name_off:end].decode(errors='ignore')
        # if name is a number, treat as pid entry
        if name.isdigit():
            try:
                pids.add(int(name))
            except:
                pass
        i += reclen
    return pids

# user-space: maintain a "trusted" active PID set by scanning /proc
def get_active_pids():
    p = set()
    for name in os.listdir("/proc"):
        if name.isdigit():
            p.add(int(name))
    return p

# Shared data between threads
trusted_pids = get_active_pids()
trusted_lock = threading.Lock()

# Periodically refresh trusted pid list
def refresh_trusted_loop():
    global trusted_pids
    while True:
        new = get_active_pids()
        with trusted_lock:
            trusted_pids = new
        time.sleep(2)

# Event handler
def handle_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    buf = bytes(event.buf[:event.size])
    # parse pids from dirent buffer
    dirent_pids = parse_dirents(buf, event.size)
    with trusted_lock:
        known = trusted_pids.copy()

    # compute missing pids: known - dirent_pids
    missing = known - dirent_pids

    # filter obviously unrelated pids (like kernel threads) if you want
    # reduce noise by only alerting if missing contains a non-trivial PID and the pid > 1
    suspicious = set(x for x in missing if x > 1)

    if suspicious:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        print("%s: [ALERT] pid(s) missing from getdents64 sample (pid of caller=%d): %s" %
              (now, event.pid, sorted(list(suspicious))))
        # optionally, print sample of dirent_pids
        # print("dirent returned pids (sample):", sorted(dirent_pids)[:10])

# Attach perf handler
b["events"].open_perf_buffer(handle_event, page_cnt=16)

# start trusted refresh thread
t = threading.Thread(target=refresh_trusted_loop, daemon=True)
t.start()

print("Starting detection. Press Ctrl-C to stop.")
try:
    while True:
        b.perf_buffer_poll(timeout=1000)
except KeyboardInterrupt:
    print("Exiting.")
