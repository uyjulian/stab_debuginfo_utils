
import struct
import sys
import pprint
import io

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section, StabSection, StringTableSection

stab_ntype_table = {
    0x00 : "UNDF",
    0x20 : "GSYM",
    0x22 : "FNAME",
    0x24 : "FUN",
    0x26 : "STSYM",
    0x28 : "LCSYM",
    0x2a : "MAIN",
    0x2c : "ROSYM",
    0x2e : "BNSYM",
    0x30 : "PC",
    0x32 : "NSYMS",
    0x34 : "NOMAP",
    0x38 : "OBJ",
    0x3c : "OPT",
    0x40 : "RSYM",
    0x42 : "M2C",
    0x44 : "SLINE",
    0x46 : "DSLINE",
    0x48 : "BSLINE",
    0x4a : "DEFD",
    0x4C : "FLINE",
    0x4E : "ENSYM",
    0x50 : "EHDECL",
    0x54 : "CATCH",
    0x60 : "SSYM",
    0x62 : "ENDM",
    0x64 : "SO",
    0x66 : "OSO",
    0x6c : "ALIAS",
    0x80 : "LSYM",
    0x82 : "BINCL",
    0x84 : "SOL",
    0xa0 : "PSYM",
    0xa2 : "EINCL",
    0xa4 : "ENTRY",
    0xc0 : "LBRAC",
    0xc2 : "EXCL",
    0xc4 : "SCOPE",
    0xd0 : "PATCH",
    0xe0 : "RBRAC",
    0xe2 : "BCOMM",
    0xe4 : "ECOMM",
    0xe8 : "ECOML",
    0xea : "WITH",
    0xF0 : "NBTEXT",
    0xF2 : "NBDATA",
    0xF4 : "NBBSS",
    0xF6 : "NBSTS",
    0xF8 : "NBLCS",
    0xfe : "LENG",
}

mdebug_st_value = [
    "stNil",
    "stGlobal",
    "stStatic",
    "stParam",
    "stLocal",
    "stLabel",
    "stProc",
    "stBlock",
    "stEnd",
    "stMember",
    "stTypedef",
    "stFile",
    "stRegReloc",
    "stForward",
    "stStaticProc",
    "stConstant",
    "stStaParam",
]

def read_hdrr(g):
    # HDRR structure information from coff/sym.h from binutils
    m_magic = struct.unpack("<H", g.read(2))[0] # /* to verify validity of the table */
    m_vstamp = struct.unpack("<H", g.read(2))[0] # /* version stamp */
    m_ilineMax = struct.unpack("<I", g.read(4))[0] # /* number of line number entries */
    m_cbLine = struct.unpack("<I", g.read(4))[0] # /* number of bytes for line number entries */
    m_cbLineOffset = struct.unpack("<I", g.read(4))[0] # /* offset to start of line number entries*/
    m_idnMax = struct.unpack("<I", g.read(4))[0] # /* max index into dense number table */
    m_cbDnOffset = struct.unpack("<I", g.read(4))[0] # /* offset to start dense number table */
    m_ipdMax = struct.unpack("<I", g.read(4))[0] # /* number of procedures */
    m_cbPdOffset = struct.unpack("<I", g.read(4))[0] # /* offset to procedure descriptor table */
    m_isymMax = struct.unpack("<I", g.read(4))[0] # /* number of local symbols */
    m_cbSymOffset = struct.unpack("<I", g.read(4))[0] # /* offset to start of local symbols*/
    m_ioptMax = struct.unpack("<I", g.read(4))[0] # /* max index into optimization symbol entries */
    m_cbOptOffset = struct.unpack("<I", g.read(4))[0] # /* offset to optimization symbol entries */
    m_iauxMax = struct.unpack("<I", g.read(4))[0] # /* number of auxiliary symbol entries */
    m_cbAuxOffset = struct.unpack("<I", g.read(4))[0] # /* offset to start of auxiliary symbol entries*/
    m_issMax = struct.unpack("<I", g.read(4))[0] # /* max index into local strings */
    m_cbSsOffset = struct.unpack("<I", g.read(4))[0] # /* offset to start of local strings */
    m_issExtMax = struct.unpack("<I", g.read(4))[0] # /* max index into external strings */
    m_cbSsExtOffset = struct.unpack("<I", g.read(4))[0] # /* offset to start of external strings */
    m_ifdMax = struct.unpack("<I", g.read(4))[0] # /* number of file descriptor entries */
    m_cbFdOffset = struct.unpack("<I", g.read(4))[0] # /* offset to file descriptor table */
    m_crfd = struct.unpack("<I", g.read(4))[0] # /* number of relative file descriptor entries */
    m_cbRfdOffset = struct.unpack("<I", g.read(4))[0] # /* offset to relative file descriptor table */
    m_iextMax = struct.unpack("<I", g.read(4))[0] # /* max index into external symbols */
    m_cbExtOffset = struct.unpack("<I", g.read(4))[0] # /* offset to start of external symbol entries*/
    return {
        "magic" : m_magic,
        "vstamp" : m_vstamp,
        "ilineMax" : m_ilineMax,
        "cbLine" : m_cbLine,
        "cbLineOffset" : m_cbLineOffset,
        "idnMax" : m_idnMax,
        "cbDnOffset" : m_cbDnOffset,
        "ipdMax" : m_ipdMax,
        "cbPdOffset" : m_cbPdOffset,
        "isymMax" : m_isymMax,
        "cbSymOffset" : m_cbSymOffset,
        "ioptMax" : m_ioptMax,
        "cbOptOffset" : m_cbOptOffset,
        "iauxMax" : m_iauxMax,
        "cbAuxOffset" : m_cbAuxOffset,
        "issMax" : m_issMax,
        "cbSsOffset" : m_cbSsOffset,
        "issExtMax" : m_issExtMax,
        "cbSsExtOffset" : m_cbSsExtOffset,
        "ifdMax" : m_ifdMax,
        "cbFdOffset" : m_cbFdOffset,
        "crfd" : m_crfd,
        "cbRfdOffset" : m_cbRfdOffset,
        "iextMax" : m_iextMax,
        "cbExtOffset" : m_cbExtOffset,
    }


# from coff/ecoff.h:
CODE_MASK = 0x8F300
def ECOFF_IS_STAB(sym):
    return ((sym["index"] & 0xFFF00) == CODE_MASK)
def ECOFF_MARK_STAB(code):
    return code + CODE_MASK
def ECOFF_UNMARK_STAB(code):
    return code - CODE_MASK
STABS_SYMBOL = "@stabs"

SYM_BITS1_ST_BIG = 0xFC
SYM_BITS1_ST_SH_BIG = 2
SYM_BITS1_ST_LITTLE = 0x3F
SYM_BITS1_ST_SH_LITTLE = 0

SYM_BITS1_SC_BIG = 0x03
SYM_BITS1_SC_SH_LEFT_BIG = 3
SYM_BITS1_SC_LITTLE = 0xC0
SYM_BITS1_SC_SH_LITTLE = 6

SYM_BITS2_SC_BIG = 0xE0
SYM_BITS2_SC_SH_BIG = 5
SYM_BITS2_SC_LITTLE = 0x07
SYM_BITS2_SC_SH_LEFT_LITTLE = 2

SYM_BITS2_RESERVED_BIG = 0x10
SYM_BITS2_RESERVED_LITTLE = 0x08

SYM_BITS2_INDEX_BIG = 0x0F
SYM_BITS2_INDEX_SH_LEFT_BIG = 16
SYM_BITS2_INDEX_LITTLE = 0xF0
SYM_BITS2_INDEX_SH_LITTLE = 4

SYM_BITS3_INDEX_SH_LEFT_BIG = 8
SYM_BITS3_INDEX_SH_LEFT_LITTLE = 4

SYM_BITS4_INDEX_SH_LEFT_BIG = 0
SYM_BITS4_INDEX_SH_LEFT_LITTLE = 12


def read_symr(g):
    # SYMR structure information from coff/sym.h from binutils
    m_iss = struct.unpack("<I", g.read(4))[0]
    m_value = struct.unpack("<I", g.read(4))[0]
    s_bits1 = struct.unpack("<B", g.read(1))[0]
    s_bits2 = struct.unpack("<B", g.read(1))[0]
    s_bits3 = struct.unpack("<B", g.read(1))[0]
    s_bits4 = struct.unpack("<B", g.read(1))[0]
    # Byteswap info from coff/mips.h and bfd/ecoffswap.h from binutils
    return {
        "iss" : m_iss,
        "value" : m_value,
        "st" : (s_bits1 & SYM_BITS1_ST_LITTLE) >> SYM_BITS1_ST_SH_LITTLE,
        "sc" : ((s_bits1 & SYM_BITS1_SC_LITTLE) >> SYM_BITS1_SC_SH_LITTLE) | ((s_bits2 & SYM_BITS2_SC_LITTLE) << SYM_BITS2_SC_SH_LEFT_LITTLE),
        "reserved" : 0 != (s_bits2 & SYM_BITS2_RESERVED_LITTLE),
        "index" : ((s_bits2 & SYM_BITS2_INDEX_LITTLE) >> SYM_BITS2_INDEX_SH_LITTLE) | (s_bits3 << SYM_BITS3_INDEX_SH_LEFT_LITTLE) | (s_bits4 << SYM_BITS4_INDEX_SH_LEFT_LITTLE),
    }

if True:
    stab_typeinfo = {}
    stab_typeinfo_curfile = ""
    stab_typeinfo_continuation_queue = []
    stab_typeinfo_files = {}
    with open(sys.argv[1], 'rb') as f:
        elffile = ELFFile(f)
        mdebugsect_name = ".mdebug"
        mdebugsect = elffile.get_section_by_name(mdebugsect_name)

        if isinstance(mdebugsect, Section):
            g = io.BytesIO(mdebugsect.data())
            hdrr = read_hdrr(g)
            f.seek(hdrr["cbSsOffset"])
            symtbl_index_to_offset = []
            symtbl_strs = []
            with open(sys.argv[3], "wb") as wf:
                strt = f.read(hdrr["issMax"] * 1)
                wf.write(strt)
                symtbl_strs = strt.split(b"\x00")
                lastpos = strt.find(b"\x00")
                while lastpos != -1:
                    symtbl_index_to_offset.append(lastpos)
                    lastpos = strt.find(b"\x00", lastpos + 1)
            symtbl_offset_to_index = {}
            for i in range(len(symtbl_index_to_offset)):
                symtbl_offset_to_index[symtbl_index_to_offset[i] + 1] = i
            f.seek(hdrr["cbSymOffset"])
            with open(sys.argv[2], "wb") as wf:
                for i in range(hdrr["isymMax"]):
                    # self.Elf_word('n_strx'),
                    # self.Elf_byte('n_type'),
                    # self.Elf_byte('n_other'),
                    # self.Elf_half('n_desc'),
                    # self.Elf_word('n_value'),
                    symr = read_symr(f)
                    if ECOFF_IS_STAB(symr):
                        wf.write(struct.pack("<IBBHI", symr["iss"], ECOFF_UNMARK_STAB(symr["index"]), 0, 0, symr["value"]))
                        # if ECOFF_UNMARK_STAB(symr["index"]) in stab_ntype_table:
                        #     print(stab_ntype_table[ECOFF_UNMARK_STAB(symr["index"])], symtbl_strs[symtbl_offset_to_index[symr["iss"]] + 1], symr["value"], mdebug_st_value[symr["st"]], symr["sc"])
                        # else:
                        #     print("UNTYPED", ECOFF_UNMARK_STAB(symr["index"]), symtbl_strs[symtbl_offset_to_index[symr["iss"]] + 1], symr["value"], mdebug_st_value[symr["st"]], symr["sc"])
                    else:
                        if mdebug_st_value[symr["st"]] == "stLabel" and symtbl_strs[symtbl_offset_to_index[symr["iss"]] + 1].startswith(b"$LM"):
                            wf.write(struct.pack("<IBBHI", 0, 0x44, 0, symr["index"], symr["value"]))
                        # print(symr["index"], symtbl_strs[symtbl_offset_to_index[symr["iss"]] + 1], symr["value"], mdebug_st_value[symr["st"]], symr["sc"])
        else:
            stabsect_name = ".stab"
            stabsect = elffile.get_section_by_name(stabsect_name)
            stabstrsect_name = ".stabstr"
            stabstrsect = elffile.get_section_by_name(stabstrsect_name)
            if isinstance(stabsect, StabSection):
                with open(sys.argv[2], "wb") as wf:
                    wf.write(stabsect.data())
            if isinstance(stabstrsect, StringTableSection):
                with open(sys.argv[3], "wb") as wf:
                    wf.write(stabstrsect.data())



