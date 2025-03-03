import datareader
import struct
import os
import os.path
"""
'aa01' files are used by apple for firmware patches, they contain metadata and filedata.

This tool can list and extract the contents of the aa01 file.

This is also called 'apple archive'
see https://github.com/0xilis/libNeoAppleArchive/blob/main/docs/NeoAAFieldType.md
and https://theapplewiki.com/wiki/Apple_Archive

Author: Willem Hengeveld <itsme@xs4all.nl>
"""
class Info:
    """ This mostly contains info on position and size of the other sections in the file """
    def __init__(self):
        self.idx = None
        self.idz = None
        self.siz = None
        self.typ = None
        self.yop = None
        self.lbl = None
    def __repr__(self):
        return f"t:{self.typ} y:{self.yop} lbl:{self.lbl} {self.idx or 0:010x} {self.idz or 0:08x} {self.siz or 0:08x}"


class Meta:
    """ contains metadata for the files, liek uid, gid, filemode, timestamps """
    def __init__(self):
        self.pat = None
        self.typ = None
        self.uid = None
        self.gid = None
        self.mod = None
        self.flg = None
        self.mtm = None
        self.ctm = None
    def __repr__(self):
        return f"  t:{self.typ} {self.mod or 0:07o} {self.uid} {self.gid} {self.flg} {self.mtm or 0:08x} {self.ctm or 0:08x}  {self.pat}"


class Data:
    """ This contins info on the file-type, size, and data """
    def __init__(self):
        self.pat = None
        self.typ = None
        self.flg = None
        self.dat = None
        self.dataofs = None
        self.fh = None
    def __repr__(self):
        if self.typ == ord('F'):
            return f"  {self.flg} {self.dat or 0:08x}  {self.pat}"
        elif self.typ == ord('D'):
            return f"  - ........  {self.pat}"
        else:
            return f"  {self.typ} unknown"


class Top:
    """ The top-level contains sections of info, meta and data types """
    def __init__(self):
        self.typ = None
        self.yop = None
        self.lbl = None
        self.dat = None
    def __repr__(self):
        return f"t:{self.typ} y:{self.yop} lbl:{self.lbl} dat={self.dat or 0:08x}"


def decoder(fh, cls):
    """
    Both top level and sub sections have the same kind of format.
    This function can decode all of them
    """
    o = fh.tell()
    while not fh.eof():
        fh.seek(o)
        try:
            m0 = fh.read(4)
        except EOFError:
            break

        if m0 != b'AA01':
            raise Exception('invalid AA01')
        sz = fh.read16le()
        data = fh.read(sz-6)

        ent = cls()

        rd = datareader.new(data)

        """
        there are four ways of encoding the size of the value:
         - time: S/T
         - size: A/B
         - name: P
         - rest: 1/2/4/8
        """
        def readvalue(spec):
            match spec:
                case '1': return rd.readbyte()
                case '2': return rd.read16le()
                case '4': return rd.read32le()
                case '8': return rd.read64le()
                case 'A': return rd.read16le()
                case 'B': return rd.read32le()
                case 'P':
                    sz = rd.read16le()
                    return rd.readstr(sz)
                case 'T':
                    t = rd.read64le()
                    rd.skip(4)
                    return t
                case 'S': return rd.read64le()
            raise Exception("invalid valuetype")

        # read properties
        while not rd.eof():
            tag = rd.readstr(4)
            value = readvalue(tag[3])
            setattr(ent, tag[:3].lower(), value)
        o = fh.tell()
        if hasattr(ent, "dat") and ent.dat:
            ent.dataofs = o
            ent.fh = fh
            o += ent.dat
        yield ent
        

def extract_aa01(fh):
    """ decode all sections from the aa01 file, yielding each item """
    for ent in decoder(fh, Top):
        if ent.yop == ord('M'):
            yield from decoder(fh.subreader(ent.dat), Info)
        elif ent.yop == ord('E'):
            yield from decoder(fh.subreader(ent.dat), Data)
        elif ent.yop == ord('O'):
            yield from decoder(fh.subreader(ent.dat), Meta)
        else:
            print("unknown section", ent.yop)


def copydata(ifh, ofh, size):
    """ copy 'size' byte from input 'ifh' to output 'ofh' """
    while size:
        want = min(size, 0x100000)
        data = ifh.read(want)
        if not data:
            break
        ofh.write(data)
        size -= want

def list_contents(fh):
    for e in extract_aa01(fh):
        print(e)

def extract_files(fh, savedir):
    # note: ignoring metadata, just saving the files.
    for e in extract_aa01(fh):
        if isinstance(e, Data):
            if e.dat:
                savename = os.path.join(savedir, e.pat)
                os.makedirs(os.path.dirname(savename), exist_ok=True)
                with open(savename, "wb") as ofh:
                    e.fh.seek(e.dataofs)
                    copydata(e.fh, ofh, e.dat)


def main():
    import argparse
    parser = argparse.ArgumentParser(description='aa01 decoder and extractor')
    parser.add_argument('--savedir', '-d', type=str)
    parser.add_argument('files', nargs='*', type=str)
    args = parser.parse_args()

    for fn in args.files:
        with open(fn, "rb") as fh:
            fh = datareader.new(fh)
            if args.savedir:
                extract_files(fh, args.savedir)
            else:
                list_contents(fh)

if __name__=='__main__':
    main()
