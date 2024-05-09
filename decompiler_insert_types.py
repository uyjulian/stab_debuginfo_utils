
import idc
import idaapi
import ida_frame
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_range
import ida_typeinf
import ida_nalt
import idautils
import json
import re

i386_stack_match = re.compile('\\[ebp([\\-\\+].*?)h\\]')
mips_stack_match = re.compile('\\[([\\-\\+].*?)h\\]')
idati = idaapi.get_idati()

class lvar_range_finder_t(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)

        self.ranges_usage = {}
        self.ranges_assignment = {}
        return

    def get_cur_expr_ea(self):
        i = self.parents.size() - 1
        parent = self.parents.at(i)
        while i >= 0 and (parent.is_expr() or parent.op == ida_hexrays.cit_expr):
            if parent.cexpr.ea != ida_idaapi.BADADDR:
                return parent.cexpr.ea
            i -= 1
            parent = self.parents.at(i)
        return ida_idaapi.BADADDR

    def visit_expr(self, e):
        try:
            if e.op == ida_hexrays.cot_var:
                idx = e.v.idx
                ranges = self.ranges_usage
                parent = self.parents.back()
                if parent != None and parent.is_expr():
                    parent_cexpr = parent.cexpr
                    if parent_cexpr.op == ida_hexrays.cot_asg and parent_cexpr.x == e:
                        ranges = self.ranges_assignment
                ea = self.get_cur_expr_ea()
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

all_lval_types = [
    ida_hexrays.cot_asg,
    ida_hexrays.cot_asgbor,
    ida_hexrays.cot_asgxor,
    ida_hexrays.cot_asgband,
    ida_hexrays.cot_asgadd,
    ida_hexrays.cot_asgsub,
    ida_hexrays.cot_asgmul,
    ida_hexrays.cot_asgsshr,
    ida_hexrays.cot_asgushr,
    ida_hexrays.cot_asgshl,
    ida_hexrays.cot_asgsdiv,
    ida_hexrays.cot_asgudiv,
    ida_hexrays.cot_asgsmod,
    ida_hexrays.cot_asgumod,
    ida_hexrays.cot_tern,
    ida_hexrays.cot_lor,
    ida_hexrays.cot_land,
    ida_hexrays.cot_bor,
    ida_hexrays.cot_xor,
    ida_hexrays.cot_band,
    ida_hexrays.cot_eq,
    ida_hexrays.cot_ne,
    ida_hexrays.cot_sge,
    ida_hexrays.cot_uge,
    ida_hexrays.cot_sle,
    ida_hexrays.cot_ule,
    ida_hexrays.cot_sgt,
    ida_hexrays.cot_ugt,
    ida_hexrays.cot_slt,
    ida_hexrays.cot_ult,
    ida_hexrays.cot_sshr,
    ida_hexrays.cot_ushr,
    ida_hexrays.cot_shl,
    ida_hexrays.cot_add,
    ida_hexrays.cot_sub,
    ida_hexrays.cot_mul,
    ida_hexrays.cot_sdiv,
    ida_hexrays.cot_udiv,
    ida_hexrays.cot_smod,
    ida_hexrays.cot_umod,
    ida_hexrays.cot_fadd,
    ida_hexrays.cot_fsub,
    ida_hexrays.cot_fmul,
    ida_hexrays.cot_fdiv,
    ida_hexrays.cot_fneg,
    ida_hexrays.cot_neg,
    ida_hexrays.cot_cast,
    ida_hexrays.cot_lnot,
    ida_hexrays.cot_bnot,
    ida_hexrays.cot_ptr,
    ida_hexrays.cot_ref,
    ida_hexrays.cot_postinc,
    ida_hexrays.cot_postdec,
    ida_hexrays.cot_preinc,
    ida_hexrays.cot_predec,
    ida_hexrays.cot_call,
    ida_hexrays.cot_idx,
    ida_hexrays.cot_memref,
    ida_hexrays.cot_memptr,
]

all_twoval_types = [
    ida_hexrays.cot_asg,
    ida_hexrays.cot_asgbor,
    ida_hexrays.cot_asgxor,
    ida_hexrays.cot_asgband,
    ida_hexrays.cot_asgadd,
    ida_hexrays.cot_asgsub,
    ida_hexrays.cot_asgmul,
    ida_hexrays.cot_asgsshr,
    ida_hexrays.cot_asgushr,
    ida_hexrays.cot_asgshl,
    ida_hexrays.cot_asgsdiv,
    ida_hexrays.cot_asgudiv,
    ida_hexrays.cot_asgsmod,
    ida_hexrays.cot_asgumod,
    ida_hexrays.cot_tern,
    ida_hexrays.cot_lor,
    ida_hexrays.cot_land,
    ida_hexrays.cot_bor,
    ida_hexrays.cot_xor,
    ida_hexrays.cot_band,
    ida_hexrays.cot_eq,
    ida_hexrays.cot_ne,
    ida_hexrays.cot_sge,
    ida_hexrays.cot_uge,
    ida_hexrays.cot_sle,
    ida_hexrays.cot_ule,
    ida_hexrays.cot_sgt,
    ida_hexrays.cot_ugt,
    ida_hexrays.cot_slt,
    ida_hexrays.cot_ult,
    ida_hexrays.cot_sshr,
    ida_hexrays.cot_ushr,
    ida_hexrays.cot_shl,
    ida_hexrays.cot_add,
    ida_hexrays.cot_sub,
    ida_hexrays.cot_mul,
    ida_hexrays.cot_sdiv,
    ida_hexrays.cot_udiv,
    ida_hexrays.cot_smod,
    ida_hexrays.cot_umod,
    ida_hexrays.cot_fadd,
    ida_hexrays.cot_fsub,
    ida_hexrays.cot_fmul,
    ida_hexrays.cot_fdiv,
]

class lvar_type_usage_t(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)

        self.type_usage = {}
        return

    def visit_expr(self, e):
        try:
            if e.op == ida_hexrays.cot_var:
                idx = e.v.idx
                type_usage = self.type_usage
                parent = self.parents.back()
                if parent != None and parent.is_expr():
                    parent_cexpr = parent.cexpr
                    if parent_cexpr.op in all_lval_types and parent_cexpr.x == e:
                        if idx not in type_usage:
                            type_usage[idx] = []
                        if parent_cexpr.op in all_twoval_types:
                            if parent_cexpr.y.op == ida_hexrays.cot_cast:
                                type_usage[idx].append(ida_typeinf.tinfo_t(parent_cexpr.y.x.type))
                            else:
                                type_usage[idx].append(ida_typeinf.tinfo_t(parent_cexpr.y.type))
                        else:
                            type_usage[idx].append(ida_typeinf.tinfo_t(parent_cexpr.type))
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
    ranges_usage = itfinder.ranges_usage
    ranges_assignment = itfinder.ranges_assignment
    typefinder = lvar_type_usage_t()
    typefinder.apply_to(cfunc.body, None)
    type_usage = typefinder.type_usage
    segmentations_map = {}
    retval = []
    for i in range(len(segmentations)):
        segmentations_map[datas[i]] = segmentations[i]
    for x in sorted(segmentations_map.keys()):
        retval.append([lvars_list[x], segmentations_map[x], ranges_usage[x] if x in ranges_usage else (ranges_assignment[x] if x in ranges_assignment else None), type_usage[x] if x in type_usage else None])
    return retval

def set_lvar_type_and_name(in_type_name_pairs, ea, filter_func=None):
    has_type = True
    type_name_pairs = []
    for i in range(len(in_type_name_pairs)):
        type_name_pair = in_type_name_pairs[i]
        t = type_name_pair[0]
        if isinstance(t, str):
            tif = idaapi.tinfo_t()
            decl_res = ida_typeinf.parse_decl(tif, None, t + ";", 0)
            if decl_res != None:
                t = ida_typeinf.tinfo_t(tif)
            else:
                t = None
        dic = {}
        dic["type"] = type_name_pair[0]
        dic["name"] = type_name_pair[1]
        dic["t_tinfo"] = t
        dic["index"] = i
        type_name_pairs.append(dic)

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
        lvars = [n[0] for n in in_lvars_ex]
        lvars_nameinfo = {}
        lvars_wantedinfo = {}
        # To handle the possibility of variables at different ranges, handle them all
        for i in range(len(lvars)):
            lvar = lvars[i]
            lvar_name = lvar.name
            lvars_nameinfo[lvar_name] = i
        for type_name_pair in type_name_pairs:
            t_index = type_name_pair["index"]
            name = type_name_pair["name"]
            t = type_name_pair["type"]
            t_tinfo = type_name_pair["t_tinfo"]
            filtered_lvars_i = [i for i in range(len(in_lvars_ex)) if filter_func(t_index, in_lvars_ex[i][0], in_lvars_ex[i][1], in_lvars_ex[i][2])]
            for lvar_i in filtered_lvars_i:
                lvar = lvars[lvar_i]
                new_name = None
                new_type = None
                if name != None:
                    new_name = name
                if t != None:
                    new_type = t_tinfo
                if new_name != None or new_type != None:
                    if lvar_i not in lvars_wantedinfo:
                        lvars_wantedinfo[lvar_i] = []
                    dic = {}
                    if new_name != None:
                        dic["name"] = new_name
                    if new_type != None:
                        dic["type"] = new_type
                        dic["typename"] = t
                    lvars_wantedinfo[lvar_i].append(dic)
            if len(filtered_lvars_i) == 0:
                print("couldn't find {} at {}".format(name, ea))
        def sort_typescore(x):
            return x[1]
        for lvar_i in sorted(lvars_wantedinfo):
            dics = lvars_wantedinfo[lvar_i]
            if len(dics) > 1 and in_lvars_ex[lvar_i][3] != None:
                cur_used_types = [til.dstr() for til in in_lvars_ex[lvar_i][3]]
                type_score = {}
                for dic_i in range(len(dics)):
                    dic = dics[dic_i]
                    new_type = dic["type"] if "type" in dic else None
                    if new_type != None:
                        type_score[dic_i] = cur_used_types.count(new_type.dstr())
                type_score_arr = [[x, type_score[x]] for x in type_score]
                type_score_arr.sort(key=sort_typescore, reverse=True)
                if len(type_score_arr) > 0:
                    dic_tmp = dics[type_score_arr[0][0]]
                    del dics[:]
                    dics.append(dic_tmp)
                else:
                    cur_used_types = [til for til in in_lvars_ex[lvar_i][3]]
                    cast_score = {}
                    for dic_i in range(len(dics)):
                        dic = dics[dic_i]
                        new_type = dic["type"] if "type" in dic else None
                        if new_type != None:
                            cur_score = 0
                            for used_type in cur_used_types:
                                cur_score += 1 if new_type.is_castable_to(used_type) else 0
                            cast_score[dic_i] = cur_score
                    type_score_arr = [[x, cast_score[x]] for x in cast_score]
                    type_score_arr.sort(key=sort_typescore, reverse=True)
                    if len(type_score_arr) > 0:
                        dic_tmp = dics[type_score_arr[0][0]]
                        del dics[:]
                        dics.append(dic_tmp)
        for lvar_i in sorted(lvars_wantedinfo):
            lvar = lvars[lvar_i]
            dics = lvars_wantedinfo[lvar_i]
            for dic in dics:
                if "name" in dic and lvar.name == dic["name"]:
                    del dic["name"]
                lvar_type = lvar.type()
                if "typename" in dic and (False if lvar_type == None else (lvar_type.dstr() == dic["typename"])):
                    del dic["type"]
                    del dic["typename"]
            dics_pruned = [dic for dic in dics if "name" in dic or "type" in dic]
            if len(dics_pruned) == 0:
                del lvars_wantedinfo[lvar_i]
        lvars_wantednameinfo = {}
        for lvar_i in sorted(lvars_wantedinfo):
            lvar = lvars[lvar_i]
            dic = lvars_wantedinfo[lvar_i][-1]
            new_name = dic["name"] if "name" in dic else None
            if (new_name != None) and ((new_name in lvars_nameinfo) or (new_name in lvars_wantednameinfo)):
                new_name += "_v%d" % lvar_i
            if (new_name != None) and (lvar.name == new_name):
                new_name = None
            if (new_name != None) and ((new_name in lvars_nameinfo) or (new_name in lvars_wantednameinfo)):
                new_name = make_unique_name(new_name, lvars_nameinfo.keys())
            if (new_name != None) and (lvar.name == new_name):
                new_name = None
            if new_name == None:
                if "name" in dic:
                    del dic["name"]
                    if "type" not in dic:
                        del lvars_wantedinfo[lvar_i]
            else:
                lvars_wantednameinfo[new_name] = lvar_i
                dic["name"] = new_name
        for lvar_i in sorted(lvars_wantedinfo):
            dic = lvars_wantedinfo[lvar_i][-1]
            lvar = lvars[lvar_i]
            old_name = lvar.name
            new_name = dic["name"] if "name" in dic else None
            new_type = dic["type"] if "type" in dic else None
            new_typename = dic["typename"] if "typename" in dic else None
            lsi = ida_hexrays.lvar_saved_info_t()
            lsi.ll = lvar
            modify_flags = 0
            if new_name != None:
                lsi.name = new_name
                modify_flags |= ida_hexrays.MLI_NAME
                print("changing name of {} to {}".format(old_name, new_name))
            if new_type != None:
                lsi.type = new_type
                modify_flags |= ida_hexrays.MLI_TYPE
                print("changing type of {} to {}".format(old_name, new_typename))
            if ida_hexrays.modify_user_lvar_info(ea, modify_flags, lsi):
                if old_name in lvars_nameinfo:
                    del lvars_nameinfo[old_name]
                lvars_nameinfo[new_name] = lvar_i
            else:
                print("unable to modify user lvar info")
                res = False
        if len(lvars_wantedinfo) == 0:
            print("couldn't find any vars to set at {}".format(ea))
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

    d = []
    with open(x, "r") as f:
        d = json.load(f)
    info_by_func = {}
    for d1 in d:
        dic = {}
        dic["var_type"] = d1[0]
        dic["func_ea"] = d1[1]
        dic["range_start_ea"] = d1[2]
        dic["range_end_ea"] = d1[3]
        dic["type_to_set"] = d1[4]
        dic["name_to_set"] = d1[5]
        dic["ab_to_find"] = d1[6]
        if dic["func_ea"] not in info_by_func:
            info_by_func[dic["func_ea"]] = []
        info_by_func[dic["func_ea"]].append(dic)
    def sort_areasize(dic):
        return dic["range_end_ea"] - dic["range_start_ea"]
    for ea in info_by_func:
        func_info = info_by_func[ea]
        func_info.sort(key=sort_areasize, reverse=True)
    for ea in sorted([j for i in [[funcea for funcea in idautils.Functions(segea, idc.get_segm_end(segea))] for segea in idautils.Segments()] for j in i]):
        if ea not in info_by_func:
            continue
        func_info = info_by_func[ea]
        type_name_pairs = []
        for dic in func_info:
            type_name_pairs.append([dic["type_to_set"], dic["name_to_set"]])
        if True:
            # if dic["type_to_set"] in primitives:
            #     dic["type_to_set"] = None

            func_for_frame = idaapi.get_func(ea)
            func_attr_fpd = idc.get_func_attr(ea, idc.FUNCATTR_FPD)
            r = ida_range.range_t()
            ida_frame.get_frame_part(r, func_for_frame, ida_frame.FPC_SAVREGS)
            range_fpc_savregs = r.end_ea - r.start_ea
            range_fpc_savregs_start = r.start_ea
            range_fpc_savregs_end = r.end_ea

            # print("Setting lvar at %x" % ea)
            def filterX(t_index, n, segmentation, ranges):
                dic = func_info[t_index]
                if n.is_arg_var or (n.name == ""):
                    return False
                if ranges != None:
                    # Check if range of bounds
                    if ranges[0] < dic["range_start_ea"]:
                        return False
                    if ranges[1] > dic["range_end_ea"]:
                        return False
                # String parsing, unfortunately, because I couldn't find an easy way to get the ebp of the variable
                slash_pos = segmentation.find("// ")
                if slash_pos != -1:
                    x_snip = segmentation[slash_pos + 3:]
                    if len(x_snip) > 0:
                        if x_snip[0] == "[":
                            if dic["var_type"] == "stkoff":
                                # stack variable
                                if arch == "i386":
                                    matc = i386_stack_match.search(x_snip)
                                    stack_offset = None
                                    if matc != None:
                                        stack_offset = int(matc.group(1), 16)
                                    if stack_offset != None:
                                        if stack_offset == dic["ab_to_find"]:
                                            return True
                                elif arch == "mips":
                                    matc = mips_stack_match.search(x_snip)
                                    stack_offset = None
                                    if matc != None:
                                        stack_offset = int(matc.group(1), 16)
                                    if stack_offset != None:
                                        stack_offset -= range_fpc_savregs
                                        stack_offset -= func_attr_fpd
                                        if stack_offset == dic["ab_to_find"]:
                                            return True
                        else:
                            if dic["var_type"] == "reg1":
                                # register variable
                                space_pos = x_snip.find(" ")
                                x_snip_2 = x_snip
                                if space_pos != -1:
                                    x_snip_2 = x_snip[:space_pos]
                                if x_snip_2 in register_int_to_name_arch:
                                    if register_int_to_name_arch[x_snip_2] == dic["ab_to_find"]:
                                        return True
                return False
            res = set_lvar_type_and_name(type_name_pairs, ea, filterX)
            # if not res:
            #     break
            # if dic["var_type"] == "stkoff":
            #     break
    if not is_interactive_mode:
        idaapi.qexit(0)
