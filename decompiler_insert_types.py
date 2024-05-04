
import idc
import idaapi
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_typeinf
import ida_nalt
import json
import re

i386_stack_match = re.compile('\\[ebp([\\-\\+].*?)h\\]')
mips_stack_match = re.compile('\\[([\\-\\+].*?)h\\]')
idati = idaapi.get_idati()

class lvar_range_finder_t(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

        self.ranges = {}
        return

    def visit_expr(self, e):
        try:
            if e.op == ida_hexrays.cot_var:
                idx = e.v.idx
                ranges = self.ranges
                ea = e.ea
                if ea != ida_idaapi.BADADDR:
                    if idx not in ranges:
                        ranges[idx] = [None, None]
                    ranges_data = ranges[idx]
                    if ranges_data[0] == None or ranges_data[0] > ea:
                        ranges_data[0] = ea
                    if ranges_data[1] == None or ranges_data[1] < ea:
                        ranges_data[1] = ea
        except:
            pass
        return 0


def get_lvars_ex(cfunc):
    ccode = cfunc.get_pseudocode()
    lvars_list = list(cfunc.get_lvars())
    segmentations = []
    datas = []
    for ypos in range(0, cfunc.hdrlines):
        tline = ccode.at(ypos).line
        idx = 0
        idx_start = None
        idx_end = None
        last_lvar = None
        while idx < len(tline):
            ci = ida_hexrays.ctree_item_t()
            if cfunc.get_line_item(tline, idx, True, None, ci, None) and ci.citype == idaapi.VDI_LVAR:
                lvarr = lvars_list.index(ci.get_lvar())
                if lvarr != None:
                    if lvarr != last_lvar:
                        if idx_start != None and idx_end != None:
                            segmentations.append(str(ida_lines.tag_remove(tline))[idx_start:idx_end])
                            idx_start = None
                            idx_end = None
                        idx_start = idx
                        idx_end = idx
                        datas.append(lvarr)
                        last_lvar = lvarr
                    else:
                        idx_end = idx
            idx += ida_lines.tag_advance(tline[idx], 1)
        if idx_start != None:
            segmentations.append(str(ida_lines.tag_remove(tline))[idx_start:])
            idx_start = None
            idx_end = None
    if len(segmentations) != len(datas):
        raise Exception("Couldn't associate lvars with segmented text")
    itfinder = lvar_range_finder_t()
    itfinder.apply_to(cfunc.body, None)
    ranges = itfinder.ranges
    segmentations_map = {}
    retval = []
    for i in range(len(segmentations)):
        segmentations_map[datas[i]] = segmentations[i]
    for x in sorted(segmentations_map.keys()):
        retval.append([lvars_list[x], segmentations_map[x], ranges[x] if x in ranges else None])
    return retval

def set_lvar_type_and_name(t, name, ea, filter_func=None):
    has_type = True
    orig_t = t
    if isinstance(t, str):
        tif = idaapi.tinfo_t()
        decl_res = ida_typeinf.parse_decl(tif, None, t + ";", 0)
        if decl_res == None:
            t = None

    def make_unique_name(name, taken):
        if name not in taken:
            return name
        fmt = "%s_%%i" % name
        for i in range(3, 1024):
            tmpName = fmt % i
            if tmpName not in taken:
                return tmpName
        return "i_give_up"

    if filter_func == None:
        raise Exception("Need filter func")

    res = True
    func = idaapi.get_func(ea)
    if func:
        ea = func.start_ea
        cfunc = None
        try:
            cfunc = idaapi.decompile(ea)
        except ida_hexrays.DecompilationFailure as e:
            cfunc = None
        if not cfunc:
            print("couldn't decompile func at {}".format(ea))
            return False
        in_lvars_ex = get_lvars_ex(cfunc)
        in_lvars = [n[0] for n in in_lvars_ex]
        lvars = [n[0] for n in in_lvars_ex if filter_func(n[0], n[1], n[2])]
        # To handle the possibility of variables at different ranges, handle them all
        lvar_count = 0
        for lvar in lvars:
            new_name = None
            new_type = None
            if name != None and lvar.name != name:
                name_to_use = name
                if lvar_count != 0:
                    name_to_use += "_%d" % lvar_count
                names = [n.name for n in in_lvars]
                if name_to_use in names:
                    name_to_use = make_unique_name(name_to_use, names)
                print("changing name of {} to {}".format(lvar.name, name_to_use))
                new_name = name_to_use
            if t != None:
                print("changing type of {} to {}: {}".format(lvar.name, t, orig_t))
                new_type = ida_typeinf.tinfo_t(tif)
            lvar_count += 1
            if new_name != None or new_type != None:
                lsi = ida_hexrays.lvar_saved_info_t()
                lsi.ll = lvar
                modify_flags = 0
                if new_name != None:
                    lsi.name = new_name
                    modify_flags |= ida_hexrays.MLI_NAME
                if new_type != None:
                    lsi.type = new_type
                    modify_flags |= ida_hexrays.MLI_TYPE
                if not ida_hexrays.modify_user_lvar_info(ea, modify_flags, lsi):
                    print("unable to modify user lvar info")
                    res = False
        if len(lvars) == 0:
            print("couldn't find {} at {}".format(name, ea))
            res = False
        if res == True:
            ida_hexrays.mark_cfunc_dirty(ea, False)
    else:
        print("couldn't get func at {}".format(ea))
        res = False
    return res

register_int_to_name = {
    "mips" : {
        # See SYMBOLIC_REGISTER_NAMES in tc-mips.c in gdb/binutils
        "$zero" : 0 ,
        "$at" : 1 ,
        "$v0" : 2 ,
        "$v1" : 3 ,
        "$a0" : 4 ,
        "$a1" : 5 ,
        "$a2" : 6 ,
        "$a3" : 7 ,
        "$s0" : 16,
        "$s1" : 17,
        "$s2" : 18,
        "$s3" : 19,
        "$s4" : 20,
        "$s5" : 21,
        "$s6" : 22,
        "$s7" : 23,
        "$t8" : 24,
        "$t9" : 25,
        "$k0" : 26,
        "$k1" : 27,
        "$gp" : 28,
        "$sp" : 29,
        "$fp" : 30,
        "$ra" : 31,
        # O32 names
        "$t0" : 8 ,
        "$t1" : 9 ,
        "$t2" : 10,
        "$t3" : 11,
        "$t4" : 12,
        "$t5" : 13,
        "$t6" : 14,
        "$t7" : 15,
    },
    "i386" : {
        # See i386_register_names in gdb/binutils
        "eax" : 0 ,
        "ecx" : 1 ,
        "edx" : 2 ,
        "ebx" : 3 ,
        "ebp" : 4 ,
        "esp" : 5 ,
        "esi" : 6 ,
        "edi" : 7 ,
        "eip" : 8 ,
        "eflags" : 9 ,
        "cs" : 10,
        "ss" : 11,
        "ds" : 12,
        "es" : 13,
        "fs" : 14,
        "gs" : 15,
        "st0" : 16,
        "st1" : 17,
        "st2" : 18,
        "st3" : 19,
        "st4" : 20,
        "st5" : 21,
        "st6" : 22,
        "st7" : 23,
        "fctrl" : 24,
        "fstat" : 25,
        "ftag" : 26,
        "fiseg" : 27,
        "fioff" : 28,
        "foseg" : 29,
        "fooff" : 30,
        "fop" : 31,
        "xmm0" : 32,
        "xmm1" : 33,
        "xmm2" : 34,
        "xmm3" : 35,
        "xmm4" : 36,
        "xmm5" : 37,
        "xmm6" : 38,
        "xmm7" : 39,
        "mxcsr" : 40,
    },
}

if True:
    is_interactive_mode = len(idc.ARGV) == 0
    # primitives = ['bool', 'double', 'float', 'int', 'long long', 'long', 'short', 'signed char', 'unsigned char', 'unsigned int', 'unsigned long long', 'unsigned long', 'unsigned short', 'void']
    x = None
    if is_interactive_mode:
        x = ida_kernwin.ask_file(1, "*.json", "Enter name of export json file:")
    else:
        x = ida_nalt.get_input_file_path() + ".idb.lvarinfo.json"

    arch = "i386"
    info_struct = idaapi.get_inf_structure()
    proc_name = info_struct.procName
    if "mips" in proc_name:
        arch = "mips"
    elif "pc" in proc_name:
        arch = "i386"

    register_int_to_name_arch = register_int_to_name[arch]

    with open(x, "r") as f:
        d = json.load(f)
        for d1 in d:
            var_type = d1[0]
            func_ea = d1[1]
            range_start_ea = d1[2]
            range_end_ea = d1[3]
            type_to_set = d1[4]
            name_to_set = d1[5]
            ab_to_find = d1[6]
            # if type_to_set in primitives:
            #     type_to_set = None

            func_for_frame = idaapi.get_func(func_ea)
            func_attr_fpd = idc.get_func_attr(func_ea, idc.FUNCATTR_FPD)

            # print("Setting lvar at %x" % func_ea)
            def filterX(n, segmentation, ranges):
                if n.is_arg_var or (n.name == ""):
                    return False
                if ranges != None:
                    # Check if range of bounds
                    if ranges[0] < range_start_ea:
                        return False
                    if ranges[1] > range_end_ea:
                        return False
                # String parsing, unfortunately, because I couldn't find an easy way to get the ebp of the variable
                slash_pos = segmentation.find("// ")
                if slash_pos != -1:
                    x_snip = segmentation[slash_pos + 3:]
                    if len(x_snip) > 0:
                        if x_snip[0] == "[":
                            if var_type == "stkoff":
                                # stack variable
                                if arch == "i386":
                                    matc = i386_stack_match.search(x_snip)
                                    stack_offset = None
                                    if matc != None:
                                        stack_offset = int(matc.group(1), 16)
                                    if stack_offset != None:
                                        if stack_offset == ab_to_find:
                                            return True
                                elif arch == "mips":
                                    matc = mips_stack_match.search(x_snip)
                                    stack_offset = None
                                    if matc != None:
                                        stack_offset = int(matc.group(1), 16)
                                    if stack_offset != None:
                                        # For some reason, stack offset is substracted by 8
                                        stack_offset -= 8
                                        stack_offset -= func_attr_fpd
                                        if stack_offset == ab_to_find:
                                            return True
                        else:
                            if var_type == "reg1":
                                # register variable
                                space_pos = x_snip.find(" ")
                                x_snip_2 = x_snip
                                if space_pos != -1:
                                    x_snip_2 = x_snip[:space_pos]
                                if x_snip_2 in register_int_to_name_arch:
                                    if register_int_to_name_arch[x_snip_2] == ab_to_find:
                                        return True
                return False
            res = set_lvar_type_and_name(type_to_set, name_to_set, func_ea, filterX)
            # if not res:
            #     break
            # if var_type == "stkoff":
            #     break
    if not is_interactive_mode:
        idaapi.qexit(0)
