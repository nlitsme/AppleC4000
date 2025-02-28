"""
IDA loader module for apple C4000 baseband 'fwsg' firmware files.
This module provides two loaders, one arm32/thumb, the other arm64,
you will have to manually determine which applies.

These are the files currently known to be in fwsg format:

 * cdph.bin  - arm thumb
 * cdpd.bin  - arm64
 * cdpu.bin  - arm64
 * l1cs.bin  - arm64
 * rkos.bin  - arm64

Usage: copy this python file to your IDA/loaders directory

Alternatively you can also run this as a standalone command, and
print the segment list from the passed filenames.

(C) 2025 Willem Hengeveld <itsme@gsmk.de>
"""
from dataclasses import dataclass
try:
    import idaapi
except ModuleNotFoundError:
    pass
import struct
import io

def read_fwsg_format(fh):
    """
    The fwsg header is at the end of the file,
    with magic number 'fwsg' at offset: EOF-32,
    followed by and unknown flag, which is always 1,
    then the file offset to the start of the segment list,
    and the nr of entries.

    Each entry is 32 bytes and contains a virtual address,
    a file offset, a file size, a segment size, a flag and
    a name.

    I don't have a way of determining if a segment is 16/32 or 64 bits.
    """
    fh.seek(-32, io.SEEK_END)
    data = fh.read(16)
    if not data:
        raise Exception("error reading data")
    magic, flag, tableofs, nrentries = struct.unpack("<4s3L", data)
    if magic != b"fwsg":
        raise Exception("invalid magic")
    fh.seek(tableofs)

    @dataclass
    class Ent:
        vaddr: int
        fileofs: int
        filesize: int
        memsize: int
        flag: int
        name: str

        def __repr__(self):
            return f"v:{self.vaddr:08x}-{self.vaddr+self.memsize:08x}({self.memsize:08x}) f:{self.fileofs:08x}-{self.fileofs+self.filesize:08x}({self.filesize:08x})  {self.flag:x} {self.name}"

    seglist = []
    for _ in range(nrentries):
        entdata = fh.read(32)
        if not entdata:
            raise Exception("error reading data")
        vaddr, fileofs, filesize, memsize, flag, name = struct.unpack("<Q4L8s", entdata)
        seglist.append(Ent(vaddr, fileofs, filesize, memsize, flag, name.rstrip(b"\x00").decode()))
    return seglist

def dump_segment_list(seglist):
    for e in seglist:
        print(e)

def accept_file(fh, filename):
    fh.seek(-32, io.SEEK_END)
    data = fh.read(16)
    if not data:
        print("fwsg: no data")
        return 0
    magic, flag, tableofs, nrentries = struct.unpack("<4s3L", data)
    if magic != b"fwsg":
        print("fwsg: bad magic")
        return 0

    # use attribute on the filehandle to keep track of how often we were called.
    if hasattr(fh, "fwsg32"):
        return {'format': 'Apple fwsg, arm64', 'processor': 'arm' }
    else:
        setattr(fh, "fwsg32", True)
        return {'format': 'Apple fwsg', 'processor': 'arm', 'options':idaapi.ACCEPT_CONTINUE }


def load_file(fh, neflags, fmt):
    idaapi.set_processor_type('arm', idaapi.SETPROC_LOADER)
    use64 = fmt.find('64')>=0
    paddingsize = 8 if use64 else 4
    idaapi.inf_set_app_bitness(64 if use64 else 32)
    seglist = read_fwsg_format(fh)
    for e in seglist:
        idaapi.add_segm(0, e.vaddr, e.vaddr+e.memsize, e.name, "CODE")
        seg = idaapi.getseg(e.vaddr)
        seg.bitness = 2 if use64 else 1

        fh.seek(e.fileofs)
        fh.file2base(e.fileofs, e.vaddr, e.vaddr+e.filesize, 0)
        if n := (e.vaddr+e.filesize)%paddingsize:
            # padding
            for i in range(paddingsize-n):
                idaapi.patch_byte(e.vaddr+e.filesize+i, 0)

    return 1

def main():
    import sys
    for fn in sys.argv[1:]:
        print("==>", fn, "<==")
        with open(fn, "rb") as fh:
            try:
                segs = read_fwsg_format(fh)
                dump_segment_list(segs)
            except Exception as e:
                print(e)

if __name__=='__main__':
    main()
