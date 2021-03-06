
import json2pcode
import json
import sys
import os

def write_split_dispatch(ar, dt, basedir=None):
	block_depth = 0
	lastfile = ["", []]
	allfile = {}
	def deposit_file():
		if lastfile[0] != "":
			if len(lastfile[1]) > 0:
				allfile[lastfile[0]] = lastfile[1]
				lastfile[1] = []
			lastfile[0] = ""
	for x in ar:
		if x["info_type"] == "start_block":
			block_depth += 1
		elif x["info_type"] == "end_block":
			block_depth -= 1
		elif x["info_type"] == "start_compilation_unit":
			deposit_file()
			lastfile[0] = x["filename"]
		elif x["info_type"] == "start_source":
			deposit_file()
			lastfile[0] = x["filename"]
		elif x["info_type"] == "end_function":
			pass
		elif block_depth == 0:
			if (x["info_type"] == "start_function"):
				if ("addr" in x):
					addr = x["addr"]
					if addr in dt:
						lastfile[1].append("\n".join(dt[addr]) + "\n")
			else:
				lastfile[1].append(json2pcode.pr_dispatch(x))
	deposit_file()
	for fn in allfile:
		fn_split = fn.split("/")
		fn_split = [x for x in fn_split if (x != "") and (x != "..") and (x != ".")]
		fn_clean = "/".join(fn_split)
		if basedir != None:
			os.makedirs(os.path.dirname(basedir + "/" + fn_clean), exist_ok=True)
			with open(basedir + "/" + fn_clean, "w") as wf2:
				wf2.write("\n".join(allfile[fn]))
				wf2.write("\n")

import re

line_addr_re = re.compile(r"^//\-\-\-\-\- \(([0-9A-F]{8})\) \-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-$")

def split_decompiled_file(f, dt):
	current_dat = []
	current_addr = None
	for line in f.readlines():
		line = line.rstrip()
		if current_addr == None:
			line_addr_result = line_addr_re.match(line)
			if line_addr_result:
				current_addr = int(line_addr_result.group(1), 16)
		else:
			current_dat.append(line)
			if line == "}":
				dt[current_addr] = current_dat
				current_dat = []
				current_addr = None

if __name__ == "__main__":
	ar = []
	if len(sys.argv) > 1:
		with open(sys.argv[1], "r") as f:
			f.readline()
			f.readline()
			ars = "[" + f.read() + "null]"
			ar = json.loads(ars)
			ar.pop()
		json2pcode.move_anonymous_structures_to_typedefs(ar)
		json2pcode.move_named_structures_to_typedefs(ar)
		json2pcode.derive_vararg_argument(ar)
		if len(sys.argv) > 2:
			dt = {}
			with open(sys.argv[2], "r") as f:
				split_decompiled_file(f, dt)
			if len(sys.argv) > 3:
				write_split_dispatch(ar, dt, sys.argv[3])
