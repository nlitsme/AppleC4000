from abc import ABC, abstractmethod
from typing import IO
import struct

"""
FileReader and DataReader provide an easy method of deconstructing binary data into more useful types.

Author: Willem Hengeveld <itsme@xs4all.nl>
"""

class BaseReader(ABC):
    """
    Subclasses need to implement:
       eof() -> bool
       tell() -> int
       seek(pos:int, whence=SEEK_SET) -> int: ...
       read(n) -> bytes
       readbyte() -> byte
    """
    SEEK_SET = 0
    SEEK_CUR = 1
    SEEK_END = 2

    """
    Check whether the reader is currently in EOF state.
    This state is cleared after calling 'seek'.
    """
    @abstractmethod
    def eof(self) -> bool: ...

    """
    Returns the current position of the stream.
    """
    @abstractmethod
    def tell(self) -> int: ...

    """
    Repositions the current position of the stream.
    Also clears the EOF state.

    Returns the new absolute position.
    """
    @abstractmethod
    def seek(self, pos:int, whence=SEEK_SET) -> int: ...

    """
    Reads either all, or exactly `n` bytes.
    Throws EOF when more bytes are requested than available.
    """
    @abstractmethod
    def read(self, n: int = -1) -> bytes: ...

    """
    Reads 1 byte, or throws on EOF.
    """
    @abstractmethod
    def readbyte(self) -> int: ...

    """
    Skip forward by the specified nr of bytes.
    """
    def skip(self, count:int) -> None:
        self.seek(count, self.SEEK_CUR)

    """
    Reads a text string of <n> bytes.
    """
    def readstr(self, n, encoding='utf-8', strip=False):
        data = self.read(n)
        data = data.rstrip(b"\x00")
        txt = data.decode(encoding)
        if strip:
            txt = txt.rstrip()
        return txt

    """
    Read various types of integers, in either little- or big-endian style.
    """
    def read16le(self):
        return struct.unpack("<H", self.read(2))[0]
    def read24le(self):
        l, h = struct.unpack("<HB", self.read(3))
        return (h<<16) + l
    def read32le(self):
        return struct.unpack("<L", self.read(4))[0]
    def read48le(self):
        l, h = struct.unpack("<LH", self.read(6))
        return (h<<32) + l
    def read64le(self):
        return struct.unpack("<Q", self.read(8))[0]
    def read96le(self):
        l, h = struct.unpack("<QL", self.read(12))
        return (h<<64) + l
    def read128le(self):
        l, h = struct.unpack("<QQ", self.read(16))
        return (h<<64) + l

    def read16be(self):
        return struct.unpack(">H", self.read(2))[0]
    def read24be(self):
        h, l = struct.unpack(">BH", self.read(3))
        return (h<<16) + l
    def read32be(self):
        return struct.unpack(">L", self.read(4))[0]
    def read48be(self):
        h, l = struct.unpack(">HL", self.read(6))
        return (h<<32) + l
    def read64be(self):
        return struct.unpack(">Q", self.read(8))[0]
    def read96be(self):
        h, l = struct.unpack(">LQ", self.read(12))
        return (h<<64) + l
    def read128be(self):
        h, l = struct.unpack(">QQ", self.read(16))
        return (h<<64) + l
    def readfloat64be(self):
        return struct.unpack(">d", self.read(8))[0]
    def readfloat64le(self):
        return struct.unpack("<d", self.read(8))[0]

class StreamRange:
    def __init__(self, fh, start, end):
        self.fh = fh
        self.start = start
        self.end = end

    def tell(self):
        return self.fh.tell()-self.start

    def seek(self, ofs, whence=BaseReader.SEEK_SET):
        if whence==BaseReader.SEEK_SET:
            return self.fh.seek(self.start + ofs) - self.start
        elif whence==BaseReader.SEEK_CUR:
            return self.fh.seek(ofs, whence) - self.start
        elif whence==BaseReader.SEEK_END:
            return self.fh.seek(self.end + ofs, whence) - self.start

    def read(self, n=-1):
        remaining = self.end - self.tell()
        if n==-1 or n>remaining:
            n = remaining
        return self.fh.read(n)


class FileReader(BaseReader):
    def __init__(self, fh:IO):
        self.fh = fh
        self._eof = False

    def eof(self):
        # note: can't check for this!!
        # TODO: check if tell() == filesize()
        # issue: when the file changes size I would need to keep querying the filesize,
        #   which is possibly a slow operation.
        return self._eof

    def tell(self):
        return self.fh.tell()

    def seek(self, pos, whence=BaseReader.SEEK_SET):
        # reset EOF state
        self._eof = False
        return self.fh.seek(pos, whence)

    def subreader(self, n=-1):
        return FileReader(StreamRange(self.fh, self.fh.tell(), n))

    def read(self, n=-1):
        if self._eof:
            # already in EOF state.
            raise EOFError()
        data = self.fh.read(n)
        if n>0 and not data:
            # wanted more, but did not get any data.
            self._eof = True
            raise EOFError()
        elif len(data) < n:
            # it is an error to read more data than available.
            self.fh.seek(self.fh.tell()-len(data), self.SEEK_SET)
            self._eof = True
            raise EOFError()

        return data

    def readbyte(self):
        return struct.unpack(">B", self.read(1))[0]

    def readzstr(self, encoding='utf-8') -> str:
        data = []
        while not self.eof():
            try:
                byte = self.readbyte()
                if byte==0:
                    return bytes(data).decode(encoding)
                data.append(byte)
            except EOFError:
                if data:
                    return bytes(data).decode(encoding)


class DataReader(BaseReader):
    def __init__(self, data:bytes):
        self.data = data
        self.pos = 0
        self._eof = False

    def tell(self):
        return self.pos

    def seek(self, pos, whence=BaseReader.SEEK_SET):
        self._eof = False       
        match whence:           
            case self.SEEK_SET: pass
            case self.SEEK_CUR: pos += self.pos
            case self.SEEK_END: pos += len(self.data)
        if pos < 0:
            raise ValueError()
        self.pos = pos

        return pos

    def eof(self):
        return self.pos == len(self.data)

    def have(self, n):
        return self.pos + n <= len(self.data)

    def remaining(self):
        return len(self.data) - self.pos

    def readbyte(self):
        if self._eof:
            raise EOFError()
        if self.pos >= len(self.data):
            self._eof = True
            raise EOFError()
        self.pos += 1
        return self.data[self.pos-1]

    def subreader(self, n=-1):
        return DataReader(self.data[self.pos:self.pos+n])

    def read(self, n=-1):
        if self._eof:
            raise EOFError()
        if n == -1:
            n = len(self.data) - self.pos
        if self.pos+n > len(self.data):
            self._eof = True
            raise EOFError()
        self.pos += n
        return self.data[self.pos-n:self.pos]

    def readzstr(self, encoding='utf-8') -> str:
        i = self.data.find(b"\x00", self.pos)
        if i==-1:
            return self.read().decode(encoding)
        p0 = self.pos
        self.pos = i+1
        return self.data[p0:self.pos-1].decode(encoding)

import unittest
class TestReader(unittest.TestCase):
    def testRd(self):
        r = DataReader(b"abcdefghijklmnopqrstu\x00\x00xy")
        self.assertEqual(r.read(4), b"abcd")
        self.assertEqual(r.readstr(4), "efgh")
        self.assertEqual(r.readbyte(), 0x69)
        self.assertEqual(r.read32le(), 0x6d6c6b6a)
        self.assertEqual(r.read32be(), 0x6e6f7071)
        self.assertEqual(r.readstr(6), "rstu")

    def testReadRest(self):
        from io import BytesIO
        self.checkReadRest(DataReader(bytes(range(16))))
        self.checkReadRest(FileReader(BytesIO(bytes(range(16)))))

    def checkReadRest(self, r):
        self.assertEqual(r.read(4), b"\x00\x01\x02\x03")
        self.assertEqual(r.read(), bytes(range(4, 16)))

    def testSeekTell(self):
        from io import BytesIO
        self.checkSeekTell(DataReader(bytes(range(256))))
        self.checkSeekTell(FileReader(BytesIO(bytes(range(256)))))

    def checkSeekTell(self, r):
        self.assertEqual(r.tell(), 0)
        self.assertEqual(r.read(4), b"\x00\x01\x02\x03")
        self.assertEqual(r.tell(), 4)

        self.assertEqual(r.seek(8), 8)

        self.assertEqual(r.tell(), 8)
        self.assertEqual(r.read(4), b"\x08\x09\x0a\x0b")

        self.assertEqual(r.seek(-4, r.SEEK_CUR), 8)
        self.assertEqual(r.read(4), b"\x08\x09\x0a\x0b")

        r.seek(-4, r.SEEK_END)
        self.assertEqual(r.read(4), b"\xfc\xfd\xfe\xff")

        with self.assertRaises(EOFError):
            r.readbyte()

        r.seek(0)
        self.assertEqual(r.tell(), 0)
        self.assertEqual(r.read(4), b"\x00\x01\x02\x03")
        self.assertEqual(r.tell(), 4)

    def testIntReads(self):
        from io import BytesIO
        self.checkIntReads(DataReader(bytes(range(256))))
        self.checkIntReads(FileReader(BytesIO(bytes(range(256)))))

    def checkIntReads(self, r):
        self.assertEqual(r.readbyte(), 0)
        self.assertEqual(r.read16le(), 0x0201)
        self.assertEqual(r.read24le(), 0x050403)
        self.assertEqual(r.read32le(), 0x09080706)
        self.assertEqual(r.read48le(), 0x0f0e0d0c0b0a)
        self.assertEqual(r.read64le(), 0x1716151413121110)
        self.assertEqual(r.read96le(), 0x232221201f1e1d1c1b1a1918)
        self.assertEqual(r.read128le(), 0x333231302f2e2d2c2b2a292827262524)
        self.assertEqual(r.read16be(), 0x3435)
        self.assertEqual(r.read24be(), 0x363738)
        self.assertEqual(r.read32be(), 0x393a3b3c)
        self.assertEqual(r.read48be(), 0x3d3e3f404142)
        self.assertEqual(r.read64be(), 0x434445464748494a)
        self.assertEqual(r.read96be(), 0x4b4c4d4e4f50515253545556)
        self.assertEqual(r.read128be(), 0x5758595a5b5c5d5e5f60616263646566)

    def testEof(self):
        tests = [
                self.checkEof1a,
                self.checkEof1b,
                self.checkEof1c,
                self.checkEof2,
                self.checkEof3,
                self.checkEof4,
                ]
        from io import BytesIO
        for tst in tests:
            tst(DataReader(bytes(range(16))))
            tst(FileReader(BytesIO(bytes(range(16)))))

    def checkEof1a(self, r):
        self.assertEqual(r.readbyte(), 0)
        self.assertEqual(r.read(15), bytes(range(1, 16)))
        self.assertEqual(r.read(0), b"")
        with self.assertRaises(EOFError):
            r.read(1)

    def checkEof1b(self, r):
        self.assertEqual(r.readbyte(), 0)
        with self.assertRaises(EOFError):
            r.read(16)
        # check that the EOF state remains active
        with self.assertRaises(EOFError):
            r.read(1)

    def checkEof1c(self, r):
        self.assertEqual(r.readbyte(), 0)
        self.assertEqual(r.read(0), b"")
        self.assertEqual(r.read(15), bytes(range(1, 16)))
        with self.assertRaises(EOFError):
            r.read(1)

    def checkEof2(self, r):
        self.assertEqual(r.read(16), bytes(range(16)))
        with self.assertRaises(EOFError):
            r.read(1)

    def checkEof3(self, r):
        self.assertEqual(r.read(16), bytes(range(16)))
        r.seek(15)
        with self.assertRaises(EOFError):
            r.read(2)

    def checkEof4(self, r):
        self.assertEqual(r.read(16), bytes(range(16)))
        r.seek(15)
        self.assertEqual(r.readbyte(), 15)
        with self.assertRaises(EOFError):
            r.read(2)

def new(arg):
    if type(arg)==bytes:
        return DataReader(arg)
    return FileReader(arg)

