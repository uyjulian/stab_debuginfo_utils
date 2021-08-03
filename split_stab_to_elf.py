from makeelf.elf import *
import sys
import os
elf = ELF(e_machine=EM.EM_MIPS, e_data=ELFDATA.ELFDATA2LSB)
with open(sys.argv[1], "rb") as f:
	elf.append_section('.stab', f.read(), 0x0100)
with open(sys.argv[2], "rb") as f:
	elf.append_section('.stabstr', f.read(), 0x0200)

fd = os.open(sys.argv[3], os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
os.write(fd, bytes(elf))
os.close(fd)
