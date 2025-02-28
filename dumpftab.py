"""
Decodes an apple C4000 baseband ftab.bin firmware file

known contents of the ftab file:

CRnn, RPnn, Rnnn  - lzfse compressed files, unknown purpose
rcpi  - contains sha384 hashes of all sections
bver, ibdt, l1c2, ARC2  - various small files
ARC1, CAR2, CAR3  - unknown
GNS1  - arcv2 binary
apmu, pmfw  - arm thumb binaries
illb  - arm64 binary
cdph  - 'fwsg' arm thumb binary
cdpd, cdpu, rkos, l1cs - 'fwsg' arm64 binaries

(C) 2025 Willem Hengeveld <itsme@gsmk.de>
"""
from dataclasses import dataclass
import struct
import os.path

def loadftab(fh):
    """
    read the ftab header
    """
    hdrdata = fh.read(48)
    hdrfields = struct.unpack("<8L", hdrdata[:32])
    magic = hdrdata[32:40].decode()
    nrentries, zero = struct.unpack("<2L", hdrdata[40:])
    if magic != 'rkosftab':
        raise Exception("invalid magic")

    @dataclass
    class Ent:
        tag: str
        ofs: int
        size: int
        zero: int

    entries = []

    for _ in range(nrentries):
        entdata = fh.read(16)
        tag, ofs, size, zero = struct.unpack("<4s3L", entdata)

        entries.append(Ent(tag.decode(), ofs, size, zero))

    return entries

def dump_ftab_list(ents, fh):
    """
    prints the entries from the ftab list, each with the first and last 32 bytes of the sections.
    """
    prevend = 0
    for e in ents:
        if prevend and e.ofs-prevend>=4:
            print(f"gap: {prevend:08x}-{e.ofs:08x}({e.ofs-prevend:x})")

        fh.seek(e.ofs)
        headdata = fh.read(min(e.size, 32))
        taildata = b""
        if e.size>32:
            ofs2 = max(e.ofs+e.size-32, e.ofs+32)
            fh.seek(ofs2)
            taildata = fh.read(e.ofs+e.size-ofs2)
        print(f"{e.tag:4} {e.ofs:08x}-{e.ofs+e.size:08x}({e.size:08x}) {e.zero:08x} {headdata.hex()} .. {taildata.hex()}")
        prevend = e.ofs+e.size

def extract_ftab_entries(ents, fh, savedir):
    """
    splits ftab file in separate files.
    """
    for e in ents:
        fh.seek(e.ofs)
        with open(os.path.join(savedir, f"{e.tag}.bin"), "wb") as ofh:
            remaining = e.size
            while remaining:
                want = min(remaining, 0x100000)
                data = fh.read(want)
                ofh.write(data)
                remaining -= want


def main():
    import argparse
    parser = argparse.ArgumentParser(description='ftab decoder')
    parser.add_argument('--savedir', '-d', type=str)
    parser.add_argument('files', nargs='*', type=str)
    args = parser.parse_args()

    for fn in args.files:
        with open(fn, "rb") as fh:
            print("==>", fn, "<==")
            ents = loadftab(fh)
            if args.savedir:
                extract_ftab_entries(ents, fh, args.savedir)
            else:
                dump_ftab_list(ents, fh)

if __name__=='__main__':
    main()
