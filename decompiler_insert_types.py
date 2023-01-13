
import idaapi
import ida_hexrays
import ida_kernwin
import ida_typeinf
import ida_nalt
import json

idati = idaapi.get_idati()

def set_lvar_type_and_name(t, name, ea, filter_func=None):
    has_type = True
    orig_t = t
    if isinstance(t, str):
        type_tuple = idaapi.get_named_type(None, t, 1)
        tif = idaapi.tinfo_t()
        if type_tuple == None:
            t = None
        else:
            if tif.get_numbered_type(idaapi.cvar.idati, type_tuple[6]):
                t = tif
            else:
                print("couldn't convert {} into tinfo_t".format(t))
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
        cfunc = idaapi.decompile(ea)
        if not cfunc:
            return False
        in_lvars = cfunc.get_lvars()
        lvars = [n for n in in_lvars if filter_func(n)]
        if len(lvars) >= 1:
            lvar = lvars[0]
            new_name = None
            new_type = None
            if name != None and lvar.name != name:
                names = [n.name for n in in_lvars]
                if name in names:
                    name = make_unique_name(name, names)
                print("changing name of {} to {}".format(lvar.name, name))
                new_name = name
            if t != None:
                print("changing type of {} to {}: {}".format(lvar.name, t, orig_t))
                new_type = ida_typeinf.tinfo_t(tif)
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
        else:
            print("couldn't find {} at {}".format(name, ea))
            res = False
    else:
        print("couldn't get func at {}".format(ea))
        res = False
    return res

if True:
    is_interactive_mode = False
    # primitives = ['bool', 'double', 'float', 'int', 'long long', 'long', 'short', 'signed char', 'unsigned char', 'unsigned int', 'unsigned long long', 'unsigned long', 'unsigned short', 'void']
    x = None
    if is_interactive_mode:
        x = ida_kernwin.ask_file(1, "*.json", "Enter name of export json file:")
    else:
        x = ida_nalt.get_input_file_path() + ".idb.lvarinfo.json"
    with open(x, "r") as f:
        d = json.load(f)
        for d1 in d:
            type_to_set = d1[3]
            # if type_to_set in primitives:
            #     type_to_set = None

            frame_sz = idaapi.get_frame_size(idaapi.get_func(d1[1]))

            # print("Setting lvar at %x" % d1[1])
            def filterX(n):
                if n.is_arg_var or (n.name == ""):
                    return False
                if d1[0] == "reg1":
                    if n.is_reg1() and not n.is_reg2() and not n.has_user_name:
                        # ida_hexrays.get_mreg_name
                        reg1_offs_in = d1[5]
                        reg1_offs = ida_hexrays.mreg2reg(n.get_reg1(), 4)
                        # print(reg1_offs, reg1_offs_in)
                        return n.is_reg1() and reg1_offs_in == reg1_offs
                elif d1[0] == "stkoff":
                    if n.is_stk_var():
                        stkoff_offs_in = frame_sz - d1[5]
                        stkoff_offs = n.get_stkoff()
                        # print(stkoff_offs, stkoff_offs_in)
                        return n.is_stk_var() and stkoff_offs_in == stkoff_offs
                return False
            res = set_lvar_type_and_name(type_to_set, d1[4], d1[1], filterX)
            # if not res:
            #     break
            # if d1[0] == "stkoff":
            #     break
    if not is_interactive_mode:
        idaapi.qexit(0)
