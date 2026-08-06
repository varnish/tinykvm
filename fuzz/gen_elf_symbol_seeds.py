#!/usr/bin/env python3
"""Seed corpus for elfsymfuzzer.

The bugs this target is aimed at need specific header field values -- an
e_shnum past the end of the file, a symtab sh_size larger than the image, an
offset that wraps 2^64 -- and bit-flipping a valid ELF essentially never
produces them. Each seed here is a minimal 64-bit ELF with exactly one such
field poisoned.

Input format matches the harness: rip:u64, name_len:u8, name, then the image.

Scope note: the phdr-side wraps in is_dynamic_elf()/elf_load_ph belong to the
elffuzzer target, which drives the loader. This target never calls them, so
seeds for them would be dead weight here.

    ./gen_elf_symbol_seeds.py <outdir>
"""
import os
import struct
import sys

EHDR_SIZE = 64
SHDR_SIZE = 64
SYM_SIZE = 24


def ehdr(e_shoff, e_shnum, e_shstrndx):
    return b''.join([
        b'\x7fELF\x02\x01\x01\x00', b'\x00' * 8,   # e_ident
        struct.pack('<H', 2),                       # e_type = ET_EXEC
        struct.pack('<H', 0x3e),                    # e_machine = x86-64
        struct.pack('<I', 1),                       # e_version
        struct.pack('<Q', 0x401000),                # e_entry
        struct.pack('<Q', 0),   # e_phoff
        struct.pack('<Q', e_shoff),
        struct.pack('<I', 0),                       # e_flags
        struct.pack('<H', EHDR_SIZE),
        struct.pack('<H', 56), struct.pack('<H', 0),
        struct.pack('<H', SHDR_SIZE), struct.pack('<H', e_shnum),
        struct.pack('<H', e_shstrndx),
    ])


def shdr(name, sh_type, offset, size, entsize=0, link=0, addr=0):
    return struct.pack('<IIQQQQIIQQ', name, sh_type, 0, addr, offset, size,
                       link, 0, 1, entsize)


def pad8(blob):
    """Real linkers 8-align .symtab. An unaligned one makes the Elf64_Sym cast
    in resolve_symbol() UB, which UBSan reports before the loop can reach the
    bug a seed is actually aiming at -- so align deliberately, and leave the
    misalignment to the one seed below that targets it on purpose."""
    return blob + b'\x00' * (-len(blob) % 8)


def seed(rip, name, image):
    nb = name.encode()
    return struct.pack('<Q', rip) + bytes([len(nb)]) + nb + image


def seeds():
    out = {}

    # A plausible, well-formed-ish baseline: shstrtab plus a symtab/strtab
    # pair with one symbol. Mutation has somewhere sane to start from.
    names = pad8(b'\x00.shstrtab\x00.symtab\x00.strtab\x00')
    syms = struct.pack('<IBBHQQ', 1, 0x12, 0, 1, 0x401000, 0x20)
    strs = b'\x00main\x00'
    base = EHDR_SIZE + 4 * SHDR_SIZE
    o_names, o_syms, o_strs = base, base + len(names), base + len(names) + len(syms)
    shdrs = [
        shdr(0, 0, 0, 0),
        shdr(1, 3, o_names, len(names)),                       # .shstrtab
        shdr(11, 2, o_syms, len(syms), SYM_SIZE, link=3),      # .symtab
        shdr(19, 3, o_strs, len(strs)),                        # .strtab
    ]
    valid = ehdr(EHDR_SIZE, 4, 1) + b''.join(shdrs) + names + syms + strs
    out['valid'] = seed(0x401000, 'main', valid)

    # e_shnum far past the end: the walker indexes shdr[i] off the end of the
    # image, then chases sh_name into unmapped memory.
    #
    # The searched section must genuinely be absent, or the loop returns on the
    # match long before it runs off the end. section_by_name() is only ever
    # called for ".symtab" and ".strtab", so the table here holds neither.
    stub_names = b'\x00.shstrtab\x00'
    stub = [shdr(0, 0, 0, 0), shdr(1, 3, EHDR_SIZE + 2 * SHDR_SIZE, len(stub_names))]
    out['shnum_huge'] = seed(0x401000, 'main',
                             ehdr(EHDR_SIZE, 0xFFFF, 1) + b''.join(stub) + stub_names)

    # e_shstrndx past e_shnum: the string table header itself is out of range,
    # so `strings` is already a wild pointer before the loop even starts.
    out['shstrndx_oob'] = seed(0x401000, 'main',
                               ehdr(EHDR_SIZE, 2, 0xFFFE) + b''.join(stub) + stub_names)

    # e_shoff + e_shnum * 64 wraps 2^64.
    out['shoff_wrap'] = seed(0x401000, 'main',
                             ehdr(0xFFFFFFFFFFFFFF00, 0x400, 1) + b''.join(shdrs))

    # .symtab claims 16MB inside a 24-byte file: the symbol loop runs off the
    # end, and strcmp() follows each st_name.
    big = list(shdrs)
    big[2] = shdr(11, 2, o_syms, 0x1000000, SYM_SIZE, link=3)
    out['symtab_size_huge'] = seed(0x401000, 'main',
                                   ehdr(EHDR_SIZE, 4, 1) + b''.join(big)
                                   + names + syms + strs)

    # st_name far outside .strtab: &strtab[st_name] is a wild pointer, which
    # snprintf("%s") then reads as a string.
    wild = struct.pack('<IBBHQQ', 0xFFFFF0, 0x12, 0, 1, 0x401000, 0x20)
    out['stname_wild'] = seed(0x401000, 'main',
                              ehdr(EHDR_SIZE, 4, 1) + b''.join(shdrs)
                              + names + wild + strs)

    # A symbol name longer than resolve()'s 2048-byte format buffer, which is
    # what makes snprintf report a would-be length past the end.
    long_name = b'\x00' + b'A' * 4096 + b'\x00'
    lsyms = struct.pack('<IBBHQQ', 1, 0x12, 0, 1, 0x401000, 0x2000)
    lbase = EHDR_SIZE + 4 * SHDR_SIZE
    lo_n, lo_sy, lo_st = lbase, lbase + len(names), lbase + len(names) + len(lsyms)
    lshdrs = [
        shdr(0, 0, 0, 0),
        shdr(1, 3, lo_n, len(names)),
        shdr(11, 2, lo_sy, len(lsyms), SYM_SIZE, link=3),
        shdr(19, 3, lo_st, len(long_name)),
    ]
    out['symbol_name_4k'] = seed(0x401800, 'A' * 64,
                                 ehdr(EHDR_SIZE, 4, 1) + b''.join(lshdrs)
                                 + names + lsyms + long_name)

    # Truncated to just the ELF header: everything downstream is out of range.
    out['header_only'] = seed(0x401000, 'main', ehdr(EHDR_SIZE, 4, 1))

    # .symtab at a deliberately odd offset. resolve_symbol() casts the file
    # offset straight to Elf64_Sym* with no alignment check, so this is UB the
    # ELF author chooses. Benign on x86-64, a fault on strict-alignment
    # targets -- UBSan on AArch64 is where this one matters.
    mis_names = b'\x00.shstrtab\x00.symtab\x00.strtab\x00\x00'  # length 28: odd
    m_base = EHDR_SIZE + 4 * SHDR_SIZE
    m_n, m_sy, m_st = m_base, m_base + len(mis_names), m_base + len(mis_names) + len(syms)
    assert m_sy % 8 != 0, 'the point of this seed is a misaligned .symtab'
    mshdrs = [
        shdr(0, 0, 0, 0),
        shdr(1, 3, m_n, len(mis_names)),
        shdr(11, 2, m_sy, len(syms), SYM_SIZE, link=3),
        shdr(19, 3, m_st, len(strs)),
    ]
    out['symtab_misaligned'] = seed(0x401000, 'main',
                                    ehdr(EHDR_SIZE, 4, 1) + b''.join(mshdrs)
                                    + mis_names + syms + strs)

    return out


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)
    written = seeds()
    for name, blob in written.items():
        with open(os.path.join(outdir, name), 'wb') as f:
            f.write(blob)
    print(f'wrote {len(written)} seeds to {outdir}')


if __name__ == '__main__':
    main()
