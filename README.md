# Tools for reverse engineering apple C4000 baseband firmware

The baseband firmware is stored in an approx 185M file, with 'rkosftab

known sections:

 * `CRnn`, `RPnn`, `Rnnn`  - lzfse compressed files, unknown purpose
 * `rcpi`  - contains sha384 hashes of all sections
 * `bver`, `ibdt`, `l1c2`, `ARC2`  - various small files
 * `ARC1`, `CAR2`, `CAR3`  - unknown
 * `GNS1`  - arcv2 binary
 * `apmu`, `pmfw`  - arm thumb binaries
 * `illb`  - arm64 binary
 * `cdph`  - 'fwsg' arm thumb binary
 * `cdpd`, `cdpu`, `rkos`, `l1cs` - 'fwsg' arm64 binaries

The 'fwsg' files have the segment information at the end of the file.

# dumpftab.py

Splits the main ftab.bin file into separate parts.

# loadfwsg.py

hex-rays IDA Loader for the fwsg type binaries.
Installing this file in the IDA/loader directory will allow you to easily disassemble fwsg files.

# aa01tool.py

This tool can decode and unpack OTA firmware updates.
These updates come as .aea files, you can decrypt these sing the [ipsw](https://github.com/blacktop/ipsw) tool,
the use aa01tool to unpack.


# author

Willem Hengeveld <itsme@xs4all.nl>

