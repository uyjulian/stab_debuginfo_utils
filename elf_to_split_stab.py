
import struct
import sys
import pprint
import io

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section, StabSection, StringTableSection, SymbolTableSection
from elftools.elf.descriptions import describe_symbol_type

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

def read_null_ending_string(f):
    import itertools
    import functools
    toeof = iter(functools.partial(f.read, 1), b'')
    return sys.intern((b''.join(itertools.takewhile(b'\0'.__ne__, toeof))).decode("ASCII"))


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

SIZEOF_SYMR = 12

FDR_BITS1_LANG_BIG = 0xF8
FDR_BITS1_LANG_SH_BIG = 3
FDR_BITS1_LANG_LITTLE = 0x1F
FDR_BITS1_LANG_SH_LITTLE = 0

FDR_BITS1_FMERGE_BIG = 0x04
FDR_BITS1_FMERGE_LITTLE = 0x20

FDR_BITS1_FREADIN_BIG = 0x02
FDR_BITS1_FREADIN_LITTLE = 0x40

FDR_BITS1_FBIGENDIAN_BIG = 0x01
FDR_BITS1_FBIGENDIAN_LITTLE = 0x80

FDR_BITS2_GLEVEL_BIG = 0xC0
FDR_BITS2_GLEVEL_SH_BIG = 6
FDR_BITS2_GLEVEL_LITTLE = 0x03
FDR_BITS2_GLEVEL_SH_LITTLE = 0

def read_fdr(g):
    # FDR structure information from coff/sym.h from binutils
    m_adr = struct.unpack("<I", g.read(4))[0]
    m_rss = struct.unpack("<I", g.read(4))[0]
    m_issBase = struct.unpack("<I", g.read(4))[0]
    m_cbSs = struct.unpack("<I", g.read(4))[0]
    m_isymBase = struct.unpack("<I", g.read(4))[0]
    m_csym = struct.unpack("<I", g.read(4))[0]
    m_ilineBase = struct.unpack("<I", g.read(4))[0]
    m_cline = struct.unpack("<I", g.read(4))[0]
    m_ioptBase = struct.unpack("<I", g.read(4))[0]
    m_copt = struct.unpack("<I", g.read(4))[0]
    m_ipdFirst = struct.unpack("<H", g.read(2))[0]
    m_cpd = struct.unpack("<H", g.read(2))[0]
    m_iauxBase = struct.unpack("<I", g.read(4))[0]
    m_caux = struct.unpack("<I", g.read(4))[0]
    m_rfdBase = struct.unpack("<I", g.read(4))[0]
    m_crfd = struct.unpack("<I", g.read(4))[0]
    s_bits1 = struct.unpack("<B", g.read(1))[0]
    s_bits2 = struct.unpack("<B", g.read(1))[0]
    s_bits3 = struct.unpack("<B", g.read(1))[0]
    s_bits4 = struct.unpack("<B", g.read(1))[0]
    m_cbLineOffset = struct.unpack("<I", g.read(4))[0]
    m_cbLine = struct.unpack("<I", g.read(4))[0]
    # Byteswap info from coff/mips.h and bfd/ecoffswap.h from binutils
    return {
        "adr" : m_adr,
        "rss" : m_rss,
        "issBase" : m_issBase,
        "cbSs" : m_cbSs,
        "isymBase" : m_isymBase,
        "csym" : m_csym,
        "ilineBase" : m_ilineBase,
        "cline" : m_cline,
        "ioptBase" : m_ioptBase,
        "copt" : m_copt,
        "ipdFirst" : m_ipdFirst,
        "cpd" : m_cpd,
        "iauxBase" : m_iauxBase,
        "caux" : m_caux,
        "rfdBase" : m_rfdBase,
        "crfd" : m_crfd,
        "lang" : ((s_bits1 & FDR_BITS1_LANG_LITTLE) >> FDR_BITS1_LANG_SH_LITTLE),
        "fMerge" : 0 != (s_bits1 & FDR_BITS1_FMERGE_LITTLE),
        "fReadin" : 0 != (s_bits1 & FDR_BITS1_FREADIN_LITTLE),
        "fBigendian" : 0 != (s_bits1 & FDR_BITS1_FBIGENDIAN_LITTLE),
        "glevel" : ((s_bits2 & FDR_BITS2_GLEVEL_LITTLE) >> FDR_BITS2_GLEVEL_SH_LITTLE),
        "cbLineOffset" : m_cbLineOffset,
        "cbLine" : m_cbLine,
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

        addr_to_section = {}
        for section in elffile.iter_sections():
            name = section.name
            addr = section['sh_addr']
            if addr == 0:
                continue
            if addr not in addr_to_section:
                addr_to_section[addr] = name

        addr_to_symbol = {}
        for section in elffile.iter_sections():
            if isinstance(section, SymbolTableSection):
                for cnt, symbol in enumerate(section.iter_symbols()):
                    if describe_symbol_type(symbol["st_info"]["type"]) != "NOTYPE":
                        continue
                    name = symbol.name
                    if name in ["", "_retonly", "gcc2_compiled.", "__gnu_compiled_c"] or name[:1] == ".":
                        continue
                    addr = symbol['st_value']

                    if addr not in addr_to_symbol:
                        addr_to_symbol[addr] = name

        if isinstance(mdebugsect, Section):
            g = io.BytesIO(mdebugsect.data())
            hdrr = read_hdrr(g)
            f.seek(hdrr["cbSsOffset"])
            g2 = None
            with open(sys.argv[3], "wb") as wf:
                strt = f.read(hdrr["issMax"] * 1)
                wf.write(strt)
                g2 = io.BytesIO(strt)
            ifds = []
            f.seek(hdrr["cbFdOffset"])
            for i in range(hdrr["ifdMax"]):
                fdr = read_fdr(f)
                ifds.append(fdr)
            wrote_header = False
            symcount = 0
            for fdr in ifds:
                symcount += fdr["csym"]
            with open(sys.argv[2], "wb") as wf:
                bracket_depth = 0
                largest_addr = 0
                so_encountered = 0
                last_so_value = 0
                last_fun_value = 0
                for fdr in ifds:
                    isyms = []
                    f.seek(hdrr["cbSymOffset"] + (fdr["isymBase"] * SIZEOF_SYMR))
                    for i in range(fdr["csym"]):
                        isyms.append(read_symr(f))
                    for symr in isyms:
                        # self.Elf_word('n_strx'),
                        # self.Elf_byte('n_type'),
                        # self.Elf_byte('n_other'),
                        # self.Elf_half('n_desc'),
                        # self.Elf_word('n_value'),
                        offs = fdr["issBase"] + symr["iss"]
                        g2.seek(offs)
                        strrr = read_null_ending_string(g2)
                        if ECOFF_IS_STAB(symr):
                            stab_unmarked = ECOFF_UNMARK_STAB(symr["index"])
                            if (stab_unmarked == 0x00):
                                largest_addr = 0
                                last_so_value = 0
                                last_fun_value = 0
                                if wrote_header:
                                    continue
                                wrote_header = True
                            value = symr["value"]
                            if stab_unmarked in stab_ntype_table:
                                if stab_ntype_table[stab_unmarked] == "FUN":
                                    last_fun_value = value
                                if stab_ntype_table[stab_unmarked] == "LBRAC":
                                    bracket_depth += 1
                                if stab_ntype_table[stab_unmarked] == "RBRAC":
                                    bracket_depth -= 1
                                if stab_ntype_table[stab_unmarked] == "SO" and strrr != "":
                                    last_so_value = value
                                    if so_encountered != 2:
                                        so_encountered += 1
                                    else:
                                        # XXX: check if offset 0 is actually null string
                                        wf.write(struct.pack("<IBBHI", 0, 0x64, 0, 0, largest_addr))
                                if (stab_ntype_table[stab_unmarked] == "STSYM") and (bracket_depth != 0):
                                    # Value is offset from some section, figure out which section it is.
                                    strrr_symbol = strrr
                                    strrr_symbol_colon_pos = strrr_symbol.find(":")
                                    if strrr_symbol_colon_pos != -1:
                                        strrr_symbol = strrr_symbol[:strrr_symbol_colon_pos]
                                    found_possible_addrs = []
                                    for symbol_addr in addr_to_symbol:
                                        symbol = addr_to_symbol[symbol_addr]
                                        symbol_period_pos = symbol.find(".")
                                        if symbol_period_pos != -1:
                                            symbol = symbol[:symbol_period_pos]
                                            if strrr_symbol == symbol:
                                                found_possible_addrs.append(symbol_addr)

                                    for section_addr in addr_to_section:
                                        value_added = value + section_addr
                                        if value_added in found_possible_addrs:
                                            value = value_added
                                            break
                                elif (stab_ntype_table[stab_unmarked] in ["STSYM", "LCSYM", "GSYM"]) and (bracket_depth == 0):
                                    # Correct the offset to that specified in the symbol table.
                                    strrr_symbol = strrr
                                    strrr_symbol_colon_pos = strrr_symbol.find(":")
                                    if strrr_symbol_colon_pos != -1:
                                        strrr_symbol = strrr_symbol[:strrr_symbol_colon_pos]
                                    found_possible_addrs = []
                                    for symbol_addr in addr_to_symbol:
                                        symbol = addr_to_symbol[symbol_addr]
                                        symbol_period_pos = symbol.find(".")
                                        if symbol_period_pos == -1:
                                            if strrr_symbol == symbol:
                                                value = symbol_addr
                                                break
                                if stab_ntype_table[stab_unmarked] in ["RBRAC"]:
                                    # need to relocate it relative to global
                                    value_tmp = value + last_so_value
                                    if value_tmp > largest_addr:
                                        largest_addr = value_tmp
                                if stab_ntype_table[stab_unmarked] in ["LBRAC", "RBRAC"]:
                                    # need to relocate it relative to function
                                    value += last_so_value
                                    value -= last_fun_value
                                if stab_ntype_table[stab_unmarked] in ["FUN", "SO"]:
                                    if value > largest_addr:
                                        largest_addr = value
                            # if (stab_ntype_table[stab_unmarked] in ["LBRAC", "RBRAC"]):
                            #     offs = fdr["issBase"]

                            desc = 0
                            if stab_unmarked == 0x00:
                                desc = symcount
                                value = hdrr["issMax"]
                            wf.write(struct.pack("<IBBHI", offs, stab_unmarked, 0, desc, value))
                if bracket_depth != 0:
                    raise Exception("XXX: bracket depth should be 0 at exit!")
                # XXX: check if offset 0 is actually null string
                wf.write(struct.pack("<IBBHI", 0, 0x64, 0, 0, largest_addr))
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



