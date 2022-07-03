
import sys
import json

ar = []

walk_functbl = {}

def walk_dispatch(info, callback):
	return walk_functbl[info["info_type"]](info, callback)

def walk_start_compilation_unit(info, callback):
	callback(info)

def walk_start_source(info, callback):
	callback(info)

def walk_void_type(info, callback):
	callback(info)

def walk_int_type(info, callback):
	callback(info)

def walk_float_type(info, callback):
	callback(info)

def walk_complex_type(info, callback):
	walk_dispatch(info["type"], callback)
	callback(info)

def walk_bool_type(info, callback):
	callback(info)

def walk_enum_type(info, callback):
	callback(info)

def walk_pointer_type(info, callback):
	walk_dispatch(info["type"], callback)
	callback(info)

def walk_function_type(info, callback):
	walk_dispatch(info["type"], callback)
	callback(info)

def walk_array_type(info, callback):
	walk_dispatch(info["type"], callback)
	callback(info)

def walk_const_type(info, callback):
	walk_dispatch(info["type"], callback)
	callback(info)

def walk_volatile_type(info, callback):
	walk_dispatch(info["type"], callback)
	callback(info)

def walk_start_struct_type(info, callback):
	for field in info["fields"]:
		walk_dispatch(field, callback)
	callback(info)

def walk_struct_field(info, callback):
	walk_dispatch(info["type"], callback)
	callback(info)

def walk_typedef_type(info, callback):
	callback(info)

def walk_tag_type(info, callback):
	callback(info)

def walk_typdef(info, callback):
	walk_dispatch(info["type"], callback)
	callback(info)

def walk_tag(info, callback):
	walk_dispatch(info["type"], callback)
	callback(info)

def walk_int_constant(info, callback):
	callback(info)

def walk_float_constant(info, callback):
	callback(info)

def walk_typed_constant(info, callback):
	callback(info)

def walk_variable(info, callback):
	walk_dispatch(info["type"], callback)
	callback(info)

def walk_start_function(info, callback):
	for arg in info["parameters"]:
		walk_dispatch(arg, callback)
	walk_dispatch(info["type"], callback)
	callback(info)

def walk_function_parameter(info, callback):
	walk_dispatch(info["type"], callback)
	callback(info)

def walk_start_block(info, callback):
	callback(info)

def walk_lineno(info, callback):
	callback(info)

def walk_end_block(info, callback):
	callback(info)

def walk_end_function(info, callback):
	callback(info)

walk_functbl = {
	"start_compilation_unit" : walk_start_compilation_unit,
	"start_source" : walk_start_source,
	"void_type" : walk_void_type,
	"int_type" : walk_int_type,
	"float_type" : walk_float_type,
	"complex_type" : walk_complex_type,
	"bool_type" : walk_bool_type,
	"enum_type" : walk_enum_type,
	"pointer_type" : walk_pointer_type,
	"function_type" : walk_function_type,
	"array_type" : walk_array_type,
	"const_type" : walk_const_type,
	"volatile_type" : walk_volatile_type,
	"start_struct_type" : walk_start_struct_type,
	"struct_field" : walk_struct_field,
	"typedef_type" : walk_typedef_type,
	"tag_type" : walk_tag_type,
	"typdef" : walk_typdef,
	"tag" : walk_tag,
	"int_constant" : walk_int_constant,
	"float_constant" : walk_float_constant,
	"typed_constant" : walk_typed_constant,
	"variable" : walk_variable,
	"start_function" : walk_start_function,
	"function_parameter" : walk_function_parameter,
	"start_block" : walk_start_block,
	"lineno" : walk_lineno,
	"end_block" : walk_end_block,
	"end_function" : walk_end_function,
}

pr_functbl = {}

special_keywords = [
	"class",
	"private",
	"protected",
	"public",
]
def pr_filter_keyword_from_name(name):
	nname = name
	if nname in special_keywords:
		nname = nname + "_"
	return nname

def pr_dispatch(info, name=None):
	return pr_functbl[info["info_type"]](info, pr_filter_keyword_from_name(name))

def pr_filter_name(name):
	nname = name
	if nname == "":
		nname = "__empty_name"
	return "" if nname == None else " " + nname

def pr_start_compilation_unit(info, name):
	return "/* compilation unit: %s */" % info["filename"]

def pr_start_source(info, name):
	return "/* include file: %s */" % info["filename"]

def pr_void_type(info, name):
	return "void%s" % (pr_filter_name(name))

def pr_int_type(info, name):
	return "%sint%d%s" % ("u" if info["unsigned"] else "", info["size"], pr_filter_name(name))

def pr_float_type(info, name):
	return "float%d%s" % (info["size"], pr_filter_name(name))

def pr_complex_type(info, name):
	return "complex %s" % (pr_dispatch(info["type"], name))

def pr_bool_type(info, name):
	return "bool%d%s" % (info["size"], pr_filter_name(name))

def pr_enum_type(info, name):
	if (len(info["names"]) == 2 and info["names"][0][0] == "False" and info["names"][1][0] == "True" and info["names"][0][1] == 0 and info["names"][1][1] == 1):
		return "bool%s" % (pr_filter_name(name))
	fieldsa = []
	for field in info["names"]:
		fieldsa.append("%s = %i" % (field[0], field[1]))
	fieldss = ", ".join(fieldsa)
	return "enum%s {%s}%s" % ((" " + info["tag"]) if "tag" in info else "", fieldss, pr_filter_name(name))

def pr_pointer_type(info, name):
	return "%s" % (pr_dispatch(info["type"],  "*" if name == None else "*" + name))

def pr_function_type(info, name):
	if "arguments" in info:
		return "/* TODO: function type with arguments */"
	return "%s (%s)()" % (pr_dispatch(info["type"]), name)

def pr_array_type(info, name):
	lower = info["lower"]
	upper = info["upper"]
	fmt = "%s"
	if lower == 0:
		if upper == -1:
			fmt = "%s[]"
		else:
			fmt = "%s" + ("[%i]" % (upper + 1))
	else:
		fmt = "%s" + ("[%i:%i]" % (lower, upper))
	return pr_dispatch(info["type"], fmt % name)

def pr_const_type(info, name):
	return "const %s" % (pr_dispatch(info["type"], name))

def pr_volatile_type(info, name):
	return "volatile %s" % (pr_dispatch(info["type"], name))

def pr_start_struct_type(info, name):
	fieldsa = []
	for field in info["fields"]:
		fieldsa.append(pr_dispatch(field))
	fieldss = " ".join(fieldsa)
	return "%s %s {%s}%s" % ("struct" if info["structp"] else "union", info["tag"] if "tag" in info else ("__anon_struct_%u" % (info["id"])), fieldss, pr_filter_name(name))

def pr_struct_field(info, name):
	# return "%s; /* bitsize %i, bitpos %i */" % (pr_dispatch(info["type"], info["name"]), info["bitsize"], info["bitpos"])
	return "%s;" % (pr_dispatch(info["type"], info["name"]))

def pr_typedef_type(info, name):
	return "%s%s" % (info["name"], pr_filter_name(name))

def pr_tag_type(info, name):
	return "%s %s%s" % (info["kind"], info["name"] if "name" in info else ("__anon_struct_%u" % (info["id"])), pr_filter_name(name))

def pr_typdef(info, name):
	return "typedef %s;" % (pr_dispatch(info["type"], info["name"]))

def pr_tag(info, name):
	return "%s;" % (pr_dispatch(info["type"], name))

def pr_int_constant(info, name):
	return "const int %s = %i;" % (info["name"], info["ab"])

def pr_float_constant(info, name):
	return "const double %s = %g;" % (info["name"], info["ab"])

def pr_typed_constant(info, name):
	return "const %s %s = %s;" % (info["type"], info["name"], info["ab"])

def pr_variable(info, name):
	# return "%s%s%s; /* 0x%08x */" % ("static " if info["static"] else "", "register " if info["register"] else "", pr_dispatch(info["type"], info["name"]), info["ab"])
	return "%s%s%s;" % ("static " if info["static"] else "", "register " if info["register"] else "", pr_dispatch(info["type"], info["name"]))

def pr_start_function(info, name):
	argsa = []
	for arg in info["parameters"]:
		argsa.append(pr_dispatch(arg))
	if "varargs" in info and info["varargs"]:
		argsa.append("...")
	argss = ", ".join(argsa)
	# return "%s %s(%s); /* 0x%08x */" % (pr_dispatch(info["type"]), info["name"], argss, info["addr"])
	return "%s %s(%s);" % (pr_dispatch(info["type"]), info["name"], argss)

def pr_function_parameter(info, name):
	typpe = pr_dispatch(info["type"], info["name"])
	if info["pointer"]:
		typpe = "register " + typpe
	return typpe

def pr_start_block(info, name):
	return "/* start block */"

def pr_lineno(info, name):
	return "/* Line number %d in %s at 0x%x */" % (info["lineno"], info["filename"], info["ab"])

def pr_end_block(info, name):
	return "/* end block */"

def pr_end_function(info, name):
	return "/* end function */"

pr_functbl = {
	"start_compilation_unit" : pr_start_compilation_unit,
	"start_source" : pr_start_source,
	"void_type" : pr_void_type,
	"int_type" : pr_int_type,
	"float_type" : pr_float_type,
	"complex_type" : pr_complex_type,
	"bool_type" : pr_bool_type,
	"enum_type" : pr_enum_type,
	"pointer_type" : pr_pointer_type,
	"function_type" : pr_function_type,
	"array_type" : pr_array_type,
	"const_type" : pr_const_type,
	"volatile_type" : pr_volatile_type,
	"start_struct_type" : pr_start_struct_type,
	"struct_field" : pr_struct_field,
	"typedef_type" : pr_typedef_type,
	"tag_type" : pr_tag_type,
	"typdef" : pr_typdef,
	"tag" : pr_tag,
	"int_constant" : pr_int_constant,
	"float_constant" : pr_float_constant,
	"typed_constant" : pr_typed_constant,
	"variable" : pr_variable,
	"start_function" : pr_start_function,
	"function_parameter" : pr_function_parameter,
	"start_block" : pr_start_block,
	"lineno" : pr_lineno,
	"end_block" : pr_end_block,
	"end_function" : pr_end_function,
}

idc_functbl = {}

def idc_dispatch(info, name=None):
	return idc_functbl[info["info_type"]](info, name)

def idc_dummy(info, name):
	return ""

builtin_types = [
	"int",
	"char",
	"long int",
	"unsigned int",
	"long unsigned int",
	"__int128",
	"__int128 unsigned",
	"long long int",
	"long long unsigned int",
	"short int",
	"short unsigned int",
	"signed char",
	"unsigned char",
	"float",
	"double",
	"long double",
	"_Float32",
	"_Float64",
	"_Float128",
	"_Float32x",
	"_Float64x",
	"_Decimal32",
	"_Decimal64",
	"_Decimal128",
	"void",
	"complex int",
	"complex float",
	"complex double",
	"complex long double",
]

def idc_typdef(info, name):
	if info["name"] in builtin_types or (pr_dispatch(info["type"]) == info["name"]):
		return ""
	return "ParseTypes(\"%s\", 0);" % (pr_typdef(info, name))

def idc_tag(info, name):
	return "ParseTypes(\"%s\", 0);" % (pr_tag(info, name))

def idc_variable(info, name):
	# return "set_name(0x%08x,\"%s\");SetType(0x%08x,\"%s\");" % (info["ab"], info["name"], info["ab"], pr_variable(info, name))
	return "SetType(0x%08x,\"%s\");" % (info["ab"], pr_variable(info, name))

def idc_start_function(info, name):
	# return "add_func(0x%08x);set_name(0x%08x,\"%s\");SetType(0x%08x,\"%s\");" % (info["addr"], info["addr"], info["name"], info["addr"], pr_start_function(info, name))
	return "SetType(0x%08x,\"%s\");" % (info["addr"], pr_start_function(info, name))

idc_functbl = {
	"start_compilation_unit" : idc_dummy,
	"start_source" : idc_dummy,
	"void_type" : idc_dummy,
	"int_type" : idc_dummy,
	"float_type" : idc_dummy,
	"complex_type" : idc_dummy,
	"bool_type" : idc_dummy,
	"enum_type" : idc_dummy,
	"pointer_type" : idc_dummy,
	"function_type" : idc_dummy,
	"array_type" : idc_dummy,
	"const_type" : idc_dummy,
	"volatile_type" : idc_dummy,
	"start_struct_type" : idc_dummy,
	"struct_field" : idc_dummy,
	"typedef_type" : idc_dummy,
	"tag_type" : idc_dummy,
	"typdef" : idc_typdef,
	"tag" : idc_tag,
	"int_constant" : idc_dummy,
	"float_constant" : idc_dummy,
	"typed_constant" : idc_dummy,
	"variable" : idc_variable,
	"start_function" : idc_start_function,
	"function_parameter" : idc_dummy,
	"start_block" : idc_dummy,
	"lineno" : idc_dummy,
	"end_block" : idc_dummy,
	"end_function" : idc_dummy,
}

# Move anonymous structures to typedefs if available
# TODO: move anonymous structures to typedefs when not available
def move_anonymous_structures_to_typedefs(ar):
	tag_types = []
	struct_types = []
	typdefs = []
	id_to_struct = {}
	id_to_typedef_name = {}
	id_to_typedef = {}
	def cb(info):
		if info["info_type"] == "typdef":
			typdefs.append(info)
		elif info["info_type"] == "start_struct_type":
			struct_types.append(info)
		elif info["info_type"] == "tag_type":
			tag_types.append(info)
	for x in ar:
		walk_dispatch(x, cb)
		for info in struct_types:
			if not ("tag" in info):
				id_to_struct[info["id"]] = info
		for info in typdefs:
			if info["type"]["info_type"] == "tag_type":
				id_to_typedef_name[info["type"]["id"]] = info["name"]
				id_to_typedef[info["type"]["id"]] = info
	for iid in id_to_struct.keys():
		# Start renaming typedefs
		if iid in id_to_typedef:
			new_typedef_struct = id_to_struct[iid].copy()
			id_to_typedef[iid]["type"] = new_typedef_struct
			id_to_struct[iid].clear()
			id_to_struct[iid]["info_type"] = "typedef_type"
			id_to_struct[iid]["name"] = id_to_typedef_name[iid]
			for info in tag_types:
				if info["info_type"] == "tag_type":
					if info["id"] == iid:
						info.clear()
						info["info_type"] = "typedef_type"
						info["name"] = id_to_typedef_name[iid]
# Move named structures to typedefs if there is such an association
def move_named_structures_to_typedefs(ar):
	tag_types = []
	struct_types = []
	typdefs = []
	id_to_struct = {}
	id_to_typedef_name = {}
	id_to_typedef = {}
	def cb(info):
		if info["info_type"] == "typdef":
			typdefs.append(info)
		elif info["info_type"] == "start_struct_type":
			struct_types.append(info)
		elif info["info_type"] == "tag_type":
			tag_types.append(info)
	for x in ar:
		walk_dispatch(x, cb)
		for info in struct_types:
			if ("tag" in info):
				id_to_struct[info["id"]] = info
		for info in typdefs:
			if info["type"]["info_type"] == "tag_type":
				id_to_typedef_name[info["type"]["id"]] = info["name"]
				id_to_typedef[info["type"]["id"]] = info
	for iid in id_to_typedef.keys():
		# Start renaming typedefs
		if iid in id_to_struct:
			for info in tag_types:
				if id_to_typedef[iid]["type"] is info:
					# new_typedef_struct = id_to_struct[iid].copy()
					# id_to_typedef[iid]["type"] = new_typedef_struct
					continue
				if info["info_type"] == "tag_type":
					if info["id"] == iid:
						info.clear()
						info["info_type"] = "typedef_type"
						info["name"] = id_to_typedef_name[iid]
			# id_to_struct[iid].clear()
			# id_to_struct[iid]["info_type"] = "typdef"
			# id_to_struct[iid]["name"] = id_to_typedef_name[iid]
			# id_to_struct[iid]["type"] = {}
			# id_to_struct[iid]["type"]["info_type"] = "tag_type"
			# id_to_struct[iid]["type"]["kind"] = "struct" if id_to_typedef[iid]["type"]["structp"] else "union"
			# id_to_struct[iid]["type"]["id"] = id_to_typedef[iid]["type"]["id"]

# Derive vararg argument for debugging information that does not contain it
def derive_vararg_argument(ar):
	func_info = None
	block_depth = 0
	has_va_list_argument = False
	has_va_list_variable = False
	for info in ar:
		if info["info_type"] == "start_function":
			if func_info == None:
				func_info = info
			else:
				raise Exception("Function information without ending block")
			for arg in info["parameters"]:
				if arg["type"]["info_type"] == "typedef_type" and arg["type"]["name"] == "va_list":
					has_va_list_argument = True
		elif info["info_type"] == "start_block":
			if block_depth == 0:
				if func_info == None:
					raise Exception("Start block without function information")
			block_depth += 1
		elif info["info_type"] == "end_block":
			block_depth -= 1
			if block_depth == 0:
				if func_info != None:
					if (not has_va_list_argument) and has_va_list_variable:
						func_info["varargs"] = True
					func_info = None
					has_va_list_argument = False
					has_va_list_variable = False
				else:
					raise Exception("End block without function information")
		elif info["info_type"] == "variable":
			if block_depth != 0:
				if info["type"]["info_type"] == "typedef_type" and info["type"]["name"] == "va_list":
					has_va_list_variable = True

def write_pr_dispatch(ar, wf):
	for x in ar:
		wf.write(pr_dispatch(x))
		wf.write("\n")

# TODO: move this to disassembler Python script
def write_idc_types(ar, wf):
	block_depth = 0
	func_queue = []
	builtin_typedef_queue = []
	trivial_typedef_queue = []
	other_queue = []
	wf.write("#include <idc.idc>\nstatic main(void) {\n")
	start_addr = 0
	end_addr = 0
	for x in ar:
		if x["info_type"] == "start_block":
			if block_depth == 0:
				start_addr = x["ab"]
			block_depth += 1
		elif x["info_type"] == "end_block":
			block_depth -= 1
		elif block_depth != 0:
			if x["info_type"] == "variable":
				if x["static"]:
					idc_txt = idc_dispatch(x)
					other_queue.append(idc_txt)
		elif block_depth == 0:
			idc_txt = idc_dispatch(x)
			if x["info_type"] == "start_function":
				func_queue.append(idc_txt)
			elif x["info_type"] == "typdef" and x["type"]["info_type"] == "typedef_type":
				builtin_typedef_queue.append(idc_txt)
			elif x["info_type"] == "typdef" and x["type"]["info_type"] == "tag_type":
				trivial_typedef_queue.append(idc_txt)
			else:
				other_queue.append(idc_txt)
	for x in builtin_typedef_queue:
		wf.write(x)
		wf.write("\n")
	for x in trivial_typedef_queue:
		wf.write(x)
		wf.write("\n")
	for x in other_queue:
		wf.write(x)
		wf.write("\n")
	for x in func_queue:
		wf.write(x)
		wf.write("\n")
	wf.write("qexit(0);\n")
	wf.write("}\n")

def deposit_stack_variable_types(start, end, varz, outinfo_py):
	for x in varz:
		if x["info_type"] == "variable" and x["static"] == False:
			if x["register"] == False:
				ab = x["ab"]
				if (ab & 0x80000000) != 0:
					outinfo_py.append(["stkoff", start, end, pr_dispatch(x["type"]), x["name"], -(ab - 0x100000000)])
			elif x["register"] == True:
				ab = x["ab"]
				outinfo_py.append(["reg1", start, end, pr_dispatch(x["type"]), x["name"], ab])

def write_hx_json_info(ar, wf):
	block_depth = 0
	outinfo_py = []
	start_addr = 0
	vars_tmp = []
	for x in ar:
		if x["info_type"] == "start_block":
			if block_depth == 0:
				start_addr = x["ab"]
			block_depth += 1
		elif x["info_type"] == "end_block":
			block_depth -= 1
			if block_depth == 0:
				deposit_stack_variable_types(start_addr, x["ab"], vars_tmp, outinfo_py)
				vars_tmp.clear()
		elif block_depth != 0:
			if x["info_type"] == "variable":
				vars_tmp.append(x)
		elif block_depth == 0:
			pass
	json.dump(obj=outinfo_py, fp=wf, indent="\t")

if __name__ == "__main__":
	ar = []
	if len(sys.argv) > 1:
		with open(sys.argv[1], "r") as f:
			f.readline()
			f.readline()
			ars = "[" + f.read() + "null]"
			ar = json.loads(ars)
			ar.pop()
		move_anonymous_structures_to_typedefs(ar)
		move_named_structures_to_typedefs(ar)
		derive_vararg_argument(ar)
		if False:
			write_pr_dispatch(ar, wf)
		if len(sys.argv) > 2:
			with open(sys.argv[2], "w") as wf:
				write_idc_types(ar, wf)
		if len(sys.argv) > 3:
			with open(sys.argv[3], "w") as wf:
				write_hx_json_info(ar, wf)









