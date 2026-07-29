#!/usr/bin/env python3
"""Generate a seed corpus for fuzz/syscall_fuzz.cpp.

libFuzzer can discover the input grammar on its own, but it would burn a long
time rediscovering the ~112 valid syscall numbers by chance. These seeds hand
it one plausible call per syscall number, plus a few multi-step sequences
(open-then-use) that single-record mutation cannot reach on its own.

Grammar (must stay in sync with syscall_fuzz.cpp):
  record := op:u8
    (op & 3) == 0 -> POKE  sel:u8 off:i16 len:u8 bytes[len]
    otherwise     -> CALL  sysno:u16 arg[6]
  arg := kind:u8 payload
    kind&3 == 0 -> u8
    kind&3 == 1 -> u64
    kind&3 == 2 -> sel:u8 off:i16
    kind&3 == 3 -> sel:u8   (index into INTERESTING)
"""
import os
import struct
import sys

# Address-table indices, in the order build_address_table() appends them.
A_ZERO = 0
A_SCRATCH = 8
A_SCRATCH_8 = 9
A_SCRATCH_64 = 10
A_PAGE_M4 = 11
A_PAGE_M1 = 12
A_PAGE = 13
A_SCRATCH_LAST = 16
A_SMALL = 18
A_MAX_M8 = 20
A_TABLE_LEN = 27

# INTERESTING[] indices for the values we care about in seeds.
I_ZERO = 0
I_ONE = 1
I_NEG1 = 19        # uint64_t(-1)
I_VFD = 29         # FileDescriptors::VFD_START (0x1000)
I_VFD1 = 30
I_VFD2 = 31

OP_POKE = 0x00
OP_CALL = 0x01


def arg_u8(v):
    return bytes([0x00, v & 0xFF])


def arg_u64(v):
    return bytes([0x01]) + struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


def arg_ptr(sel, off=0):
    return bytes([0x02, sel % A_TABLE_LEN]) + struct.pack("<h", off)


def arg_const(idx):
    return bytes([0x03, idx])


def call(sysno, args):
    assert len(args) <= 6
    args = list(args) + [arg_u8(0)] * (6 - len(args))
    return bytes([OP_CALL]) + struct.pack("<H", sysno) + b"".join(args)


def poke(sel, data, off=0):
    assert len(data) <= 255
    return bytes([OP_POKE, sel % A_TABLE_LEN]) + struct.pack("<h", off) \
        + bytes([len(data)]) + data


# A short path string; the sandbox policy rewrites it, so the content only has
# to be a plausible non-empty C string.
PATH = poke(A_SCRATCH, b"/tmp/f\x00")
# A guest iovec array: two entries pointing into scratch.
IOVEC = poke(A_SCRATCH_64, struct.pack("<QQQQ", 0, 64, 0, 64))
# A plausible timespec / small struct blob.
BLOB = poke(A_SCRATCH_8, bytes(range(64)))


def generic_seeds():
    """One call per syscall number with a mix of argument shapes."""
    out = []
    for sysno in range(0, 400):
        out.append((
            "generic_%d" % sysno,
            PATH + BLOB + call(sysno, [
                arg_const(I_VFD),
                arg_ptr(A_SCRATCH),
                arg_u8(64),
                arg_ptr(A_SCRATCH_64),
                arg_u8(0),
                arg_u8(0),
            ]),
        ))
        # Same syscall, but arg0 as a small int (fd 0/1/2, or a flag word)
        # and pointers aimed at a page boundary.
        out.append((
            "generic_edge_%d" % sysno,
            PATH + IOVEC + call(sysno, [
                arg_u8(1),
                arg_ptr(A_PAGE_M4),
                arg_const(I_NEG1),
                arg_ptr(A_PAGE_M1),
                arg_ptr(A_SCRATCH_LAST),
                arg_const(I_NEG1),
            ]),
        ))
    return out


def sequence_seeds():
    """Multi-step sequences: create a resource, then operate on it."""
    AT_FDCWD = 0xFFFFFF9C
    O_RDONLY, O_RDWR, O_CREAT = 0, 2, 0o100

    seqs = [
        # openat(AT_FDCWD, path, O_RDONLY) ; read(vfd, scratch, 64) ; close(vfd)
        ("open_read_close", PATH
            + call(257, [arg_u64(AT_FDCWD), arg_ptr(A_SCRATCH), arg_u64(O_RDONLY), arg_u8(0)])
            + call(0, [arg_const(I_VFD), arg_ptr(A_SCRATCH_64), arg_u8(64)])
            + call(3, [arg_const(I_VFD)])),
        # openat + fstat + lseek + pread64
        ("open_fstat_pread", PATH
            + call(257, [arg_u64(AT_FDCWD), arg_ptr(A_SCRATCH), arg_u64(O_RDONLY), arg_u8(0)])
            + call(5, [arg_const(I_VFD), arg_ptr(A_SCRATCH_64)])
            + call(8, [arg_const(I_VFD), arg_u8(16), arg_u8(0)])
            + call(17, [arg_const(I_VFD), arg_ptr(A_PAGE_M4), arg_u8(64), arg_u8(8)])),
        # openat(O_RDWR|O_CREAT) + write + writev + ftruncate
        ("open_write_writev", PATH + IOVEC
            + call(257, [arg_u64(AT_FDCWD), arg_ptr(A_SCRATCH), arg_u64(O_RDWR | O_CREAT), arg_u64(0o644)])
            + call(1, [arg_const(I_VFD), arg_ptr(A_SCRATCH_64), arg_u8(64)])
            + call(20, [arg_const(I_VFD), arg_ptr(A_SCRATCH_64), arg_u8(2)])
            + call(77, [arg_const(I_VFD), arg_u8(64)])),
        # socket + connect + sendto + recvfrom + getsockopt
        ("socket_connect_send", BLOB
            + call(41, [arg_u8(2), arg_u8(1), arg_u8(0)])
            + call(42, [arg_const(I_VFD), arg_ptr(A_SCRATCH_8), arg_u8(16)])
            + call(44, [arg_const(I_VFD), arg_ptr(A_SCRATCH), arg_u8(64), arg_u8(0),
                        arg_ptr(A_SCRATCH_8), arg_u8(16)])
            + call(45, [arg_const(I_VFD), arg_ptr(A_SCRATCH), arg_u8(64), arg_u8(0),
                        arg_ptr(A_SCRATCH_8), arg_ptr(A_SMALL)])
            + call(55, [arg_const(I_VFD), arg_u8(1), arg_u8(2), arg_ptr(A_SCRATCH_8), arg_ptr(A_SMALL)])),
        # pipe2 + write + read + close both ends
        ("pipe2_rw", BLOB
            + call(293, [arg_ptr(A_SCRATCH), arg_u8(0)])
            + call(1, [arg_const(I_VFD1), arg_ptr(A_SCRATCH_64), arg_u8(32)])
            + call(0, [arg_const(I_VFD), arg_ptr(A_PAGE_M4), arg_u8(32)])
            + call(3, [arg_const(I_VFD)])
            + call(3, [arg_const(I_VFD1)])),
        # socketpair + sendmsg/recvmsg with a guest msghdr
        ("socketpair_msg", BLOB + IOVEC
            + call(53, [arg_u8(1), arg_u8(1), arg_u8(0), arg_ptr(A_SCRATCH)])
            + call(46, [arg_const(I_VFD), arg_ptr(A_SCRATCH_8), arg_u8(0)])
            + call(47, [arg_const(I_VFD1), arg_ptr(A_SCRATCH_8), arg_u8(0)])),
        # epoll_create1 + epoll_ctl + epoll_wait
        ("epoll", BLOB
            + call(291, [arg_u8(0)])
            + call(41, [arg_u8(2), arg_u8(1), arg_u8(0)])
            + call(233, [arg_const(I_VFD), arg_u8(1), arg_const(I_VFD1), arg_ptr(A_SCRATCH_8)])
            + call(232, [arg_const(I_VFD), arg_ptr(A_SCRATCH_64), arg_u8(8), arg_u8(0)])),
        # eventfd2 + read/write
        ("eventfd", BLOB
            + call(290, [arg_u8(0), arg_u8(0)])
            + call(1, [arg_const(I_VFD), arg_ptr(A_SCRATCH_64), arg_u8(8)])
            + call(0, [arg_const(I_VFD), arg_ptr(A_SCRATCH_64), arg_u8(8)])),
        # mmap + mprotect + madvise + munmap over the guest address space
        ("mmap_family",
            call(9, [arg_ptr(A_ZERO), arg_u64(0x4000), arg_u8(3), arg_u64(0x22), arg_const(I_NEG1), arg_u8(0)])
            + call(10, [arg_ptr(A_SCRATCH), arg_u64(0x2000), arg_u8(3)])
            + call(28, [arg_ptr(A_SCRATCH), arg_u64(0x2000), arg_u8(4)])
            + call(25, [arg_ptr(A_SCRATCH), arg_u64(0x1000), arg_u64(0x4000), arg_u8(1)])
            + call(11, [arg_ptr(A_SCRATCH), arg_u64(0x2000)])),
        # mmap a file-backed area from an open fd
        ("mmap_file", PATH
            + call(257, [arg_u64(AT_FDCWD), arg_ptr(A_SCRATCH), arg_u64(O_RDONLY), arg_u8(0)])
            + call(9, [arg_ptr(A_ZERO), arg_u64(0x2000), arg_u8(1), arg_u8(2), arg_const(I_VFD), arg_u8(0)])),
        # clone a guest thread, then gettid/futex/sched_yield/exit
        ("threads", BLOB
            + call(56, [arg_u64(0x00010f00), arg_ptr(A_SMALL), arg_ptr(A_SCRATCH),
                        arg_ptr(A_SCRATCH_8), arg_ptr(A_SCRATCH_64)])
            + call(186, [])
            + call(202, [arg_ptr(A_SCRATCH), arg_u8(0), arg_u8(0), arg_u8(0)])
            + call(24, [])
            + call(60, [arg_u8(0)])),
        # dup family + fcntl
        ("dup_fcntl", PATH
            + call(257, [arg_u64(AT_FDCWD), arg_ptr(A_SCRATCH), arg_u64(O_RDONLY), arg_u8(0)])
            + call(32, [arg_const(I_VFD)])
            + call(33, [arg_const(I_VFD), arg_const(I_VFD2)])
            + call(292, [arg_const(I_VFD), arg_const(I_VFD2), arg_u8(0)])
            + call(72, [arg_const(I_VFD), arg_u8(3), arg_u8(0)])),
        # poll / ppoll with a guest pollfd array
        ("poll", poke(A_SCRATCH, struct.pack("<ihh", 0x1000, 1, 0) * 8)
            + call(7, [arg_ptr(A_SCRATCH), arg_u8(8), arg_u8(0)])
            + call(271, [arg_ptr(A_SCRATCH), arg_u8(8), arg_ptr(A_SCRATCH_8), arg_u8(0)])
            # a count far beyond the handler's 256-entry host array
            + call(7, [arg_ptr(A_SCRATCH), arg_u64(4096), arg_u8(0)])),
        # stat family on paths
        ("stat_paths", PATH
            + call(4, [arg_ptr(A_SCRATCH), arg_ptr(A_SCRATCH_64)])
            + call(6, [arg_ptr(A_SCRATCH), arg_ptr(A_SCRATCH_64)])
            + call(262, [arg_u64(AT_FDCWD), arg_ptr(A_SCRATCH), arg_ptr(A_SCRATCH_64), arg_u8(0)])
            + call(21, [arg_ptr(A_SCRATCH), arg_u8(4)])
            + call(89, [arg_ptr(A_SCRATCH), arg_ptr(A_SCRATCH_64), arg_u8(64)])),
        # getdents64 on a directory fd
        ("getdents", PATH
            + call(257, [arg_u64(AT_FDCWD), arg_ptr(A_SCRATCH), arg_u64(0o200000), arg_u8(0)])
            + call(217, [arg_const(I_VFD), arg_ptr(A_SCRATCH_64), arg_u64(1024)])),
        # sendfile / splice between two fds
        ("sendfile", PATH
            + call(257, [arg_u64(AT_FDCWD), arg_ptr(A_SCRATCH), arg_u64(O_RDONLY), arg_u8(0)])
            + call(257, [arg_u64(AT_FDCWD), arg_ptr(A_SCRATCH), arg_u64(O_RDWR), arg_u8(0)])
            + call(40, [arg_const(I_VFD1), arg_const(I_VFD), arg_ptr(A_SCRATCH_8), arg_u64(4096)])
            + call(275, [arg_const(I_VFD), arg_ptr(A_SCRATCH_8), arg_const(I_VFD1),
                         arg_ptr(A_SCRATCH_64), arg_u64(4096), arg_u8(0)])),
        # readv/writev with iovecs that straddle the end of the mapped region
        ("iov_straddle",
            poke(A_SCRATCH, struct.pack("<QQ", 0, 0xFFFFFFFF) * 4)
            + call(19, [arg_const(I_VFD), arg_ptr(A_SCRATCH), arg_u8(4)])
            + call(20, [arg_u8(1), arg_ptr(A_SCRATCH), arg_u8(4)])
            + call(20, [arg_u8(1), arg_ptr(A_SCRATCH_LAST), arg_u8(64)])),
        # ioctl with assorted requests
        ("ioctl", PATH + BLOB
            + call(257, [arg_u64(AT_FDCWD), arg_ptr(A_SCRATCH), arg_u64(O_RDONLY), arg_u8(0)])
            + call(16, [arg_const(I_VFD), arg_u64(0x5401), arg_ptr(A_SCRATCH_64)])
            + call(16, [arg_u8(1), arg_u64(0x5413), arg_ptr(A_SCRATCH_64)])),
        # arch_prctl / prctl / set_tid_address / sigaction
        ("prctl_signals", BLOB
            + call(158, [arg_u64(0x1002), arg_ptr(A_SCRATCH)])
            + call(157, [arg_u8(15), arg_ptr(A_SCRATCH)])
            + call(218, [arg_ptr(A_SCRATCH)])
            + call(13, [arg_u8(11), arg_ptr(A_SCRATCH_64), arg_ptr(A_PAGE_M4), arg_u8(8)])
            + call(131, [arg_ptr(A_SCRATCH), arg_ptr(A_SCRATCH_8)])),
        # brk walking past the guest's break limit
        ("brk", call(12, [arg_ptr(A_ZERO)])
            + call(12, [arg_ptr(A_SCRATCH)])
            + call(12, [arg_const(I_NEG1)])
            + call(12, [arg_ptr(A_MAX_M8)])),
        # uname/getcwd/readlink writing into guest memory near a boundary
        ("write_into_guest",
            call(63, [arg_ptr(A_PAGE_M4)])
            + call(79, [arg_ptr(A_PAGE_M1), arg_u64(4096)])
            + call(89, [arg_ptr(A_SCRATCH), arg_ptr(A_SCRATCH_LAST), arg_u64(4096)])
            + call(318, [arg_ptr(A_PAGE_M4), arg_u64(256), arg_u8(0)])),
    ]
    return seqs


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "seeds"
    os.makedirs(outdir, exist_ok=True)
    seeds = generic_seeds() + sequence_seeds()
    for name, data in seeds:
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(data)
    print("wrote %d seeds to %s" % (len(seeds), outdir))


if __name__ == "__main__":
    main()
