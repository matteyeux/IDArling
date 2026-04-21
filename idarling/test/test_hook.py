import ida_idp, ida_typeinf, ida_bytes, ida_enum, ida_hexrays


class MyIDBHooks(ida_idp.IDB_Hooks):
    def __init__(self):
        ida_idp.IDB_Hooks.__init__(self)
        print("MyIDBHooks init done")

    def make_code(self, insn):
        print("Detected a make code at 0x%x" % (insn.ea))
        return 0

    def make_data(self, ea, flags, tid, size):
        print("Detected a make data at 0x%x of size 0x%x" % (ea, size))
        return 0

    def renamed(self, ea, new_name, local_name):
        print(
            "Detected a renamed at 0x%x to %s (is_local=%s)"
            % (ea, new_name, local_name)
        )
        return 0

    def func_added(self, func):
        print("Detected a new function at 0x%x" % (func.start_ea))
        return 0

    def deleting_func(self, func):
        print("Detected a deleted function at 0x%x" % (func.start_ea))
        return 0

    def set_func_start(self, func, new_start):
        print(
            "Detected a new function start from %x to 0x%x" % (func.start_ea, new_start)
        )
        return 0

    def set_func_end(self, func, new_end):
        print("Detected a new function end to 0x%x" % (new_end))
        return 0

    def func_tail_appended(self, func, tail):
        print("Detected a new tail appended at 0x%x" % (tail.start_ea))
        return 0

    def func_tail_deleted(self, func, tail_ea):
        print("Detected a new tail deleted at 0x%x" % (tail_ea))
        return 0

    def tail_owner_changed(self, tail, owner_func, old_owner):
        print(
            "Detected a tail owner changed at 0x%x for %s" % (tail.start_ea, owner_func)
        )
        return 0

    def cmt_changed(self, ea, repeatable_cmt):
        cmt = ida_bytes.get_cmt(ea, repeatable_cmt)
        cmt = "" if not cmt else cmt
        print(
            "Detected a comment changed at 0x%x for %s, %s" % (ea, cmt, repeatable_cmt)
        )
        return 0

    def range_cmt_changed(self, kind, a, cmt, repeatable):
        print("Detected a range comment changed at 0x%x for %s" % (a.start_ea, cmt))
        return 0

    def extra_cmt_changed(self, ea, line_idx, cmt):
        print("Detected an extra comment changed at 0x%x for %s" % (ea, cmt))
        return 0

    def ti_changed(self, ea, type, fname):
        type = ida_typeinf.idc_get_type_raw(ea)
        print("Detected a ti changed at 0x%x for type: %s" % (ea, type))
        return 0

    def op_type_changed(self, ea, n):
        print("Detected an op type changed at 0x%x for %d" % (ea, n))
        return 0

    def enum_created(self, enum):
        name = ida_enum.get_enum_name(enum)
        print("Detected a new enum created: 0x%x (%s)" % (enum, name))
        return 0

    def deleting_enum(self, id):
        name = ida_enum.get_enum_name(id)
        print("Detected a enum deleted: 0x%x (%s)" % (id, name))
        return 0

    def renaming_enum(self, id, is_enum, newname):
        if is_enum:
            oldname = ida_enum.get_enum_name(id)
        else:
            oldname = ida_enum.get_enum_member_name(id)
        print(
            "Detected an enum renamed from %s to %s (is_enum=%s)"
            % (oldname, newname, is_enum)
        )
        return 0

    def enum_bf_changed(self, id):
        ename = ida_enum.get_enum_name(id)
        print("Detected a bf changed: 0x%x (%s)" % (id, ename))
        return 0

    def enum_cmt_changed(self, tid, repeatable_cmt):
        cmt = ida_enum.get_enum_cmt(tid, repeatable_cmt)
        emname = ida_enum.get_enum_name(tid)
        print(
            "Detected an enum comment changed for 0x%x (%s): %s, %s"
            % (tid, emname, cmt, repeatable_cmt)
        )
        return 0

    def enum_member_created(self, id, cid):
        ename = ida_enum.get_enum_name(id)
        name = ida_enum.get_enum_member_name(cid)
        value = ida_enum.get_enum_member_value(cid)
        bmask = ida_enum.get_enum_member_bmask(cid)
        print(
            "Detected a new enum member created: 0x%x (%s), 0x%x (%s) = 0x%x, 0x%x"
            % (id, ename, cid, name, value, bmask)
        )
        return 0

    def deleting_enum_member(self, id, cid):
        ename = ida_enum.get_enum_name(id)
        value = ida_enum.get_enum_member_value(cid)
        serial = ida_enum.get_enum_member_serial(cid)
        bmask = ida_enum.get_enum_member_bmask(cid)
        print(
            "Detected a new enum member created: 0x%x (%s), 0x%x (%s) = 0x%x, 0x%x"
            % (id, ename, cid, serial, value, bmask)
        )
        return 0

    def struc_created(self, tid):
        name = ida_struct.get_struc_name(tid)
        is_union = ida_struct.is_union(tid)
        print(
            "Detected a new struct created: 0x%x (%s) (is_union=%s)"
            % (tid, name, is_union)
        )
        return 0

    def deleting_struc(self, sptr):
        sname = ida_struct.get_struc_name(sptr.id)
        print("Detected a new struct deleted: 0x%x (%s)" % (sptr.id, sname))
        return 0

    def renaming_struc(self, id, oldname, newname):
        print("Detected a struct renamed from %s to %s" % (oldname, newname))
        return 0

    def struc_member_created(self, sptr, mptr):
        sname = ida_struct.get_struc_name(sptr.id)
        fieldname = ida_struct.get_member_name(mptr.id)
        print("Detected a struct member created %s.%s" % (sname, fieldname))
        return 0

    def struc_member_deleted(self, sptr, off1, off2):
        sname = ida_struct.get_struc_name(sptr.id)
        print("Detected a struct member deleted %s at offset 0x%x" % (sname, off2))
        return 0

    def renaming_struc_member(self, sptr, mptr, newname):
        sname = ida_struct.get_struc_name(sptr.id)
        offset = mptr.soff
        print(
            "Detected a struct member renamed %s at offset 0x%x with new name: %s"
            % (sname, offset, newname)
        )
        return 0

    def struc_cmt_changed(self, id, repeatable_cmt):
        fullname = ida_struct.get_struc_name(id)
        if "." in fullname:
            sname, smname = fullname.split(".", 1)
        else:
            sname = fullname
            smname = ""
        cmt = ida_struct.get_struc_cmt(id, repeatable_cmt)
        print(
            "Detected a struct comment changed for 0x%x (%s and %s): %s, %s"
            % (id, sname, smname, cmt, repeatable_cmt)
        )
        return 0

    def struc_member_changed(self, sptr, mptr):
        sname = ida_struct.get_struc_name(sptr.id)
        print("Detected a struct member changed %s at offset 0x%x" % (sname, mptr.eoff))
        return 0

    def expanding_struc(self, sptr, offset, delta):
        sname = ida_struct.get_struc_name(sptr.id)
        print(
            "Detected a struct expansion: %s at offset 0x%x (delta=0x%x)"
            % (sname, offset, delta)
        )
        return 0

    def segm_added(self, s):
        print(
            "Detected a segment added: %s [0x%x, 0x%x]"
            % (ida_segment.get_segm_name(s), s.start_ea, s.end_ea)
        )
        return 0

    def segm_deleted(self, start_ea, end_ea):
        print("Detected a segment deleted: [0x%x, 0x%x]" % (start_ea, end_ea))
        return 0

    def segm_start_changed(self, s, oldstart):
        print(
            "Detected a segment changed: %s start from 0x%x to 0x%x"
            % (ida_segment.get_segm_name(s), oldstart, s.start_ea)
        )
        return 0

    def segm_end_changed(self, s, oldend):
        print(
            "Detected a segment changed: %s end from 0x%x to 0x%x"
            % (ida_segment.get_segm_name(s), oldend, s.end_ea)
        )
        return 0

    def segm_name_changed(self, s, name):
        print(
            "Detected a segment name changed: %s for [0x%x, 0x%x]"
            % (name, s.start_ea, s.end_ea)
        )
        return 0

    def segm_class_changed(self, s, sclass):
        print(
            "Detected a segment class changed for start: 0x%x, class: 0x%x"
            % (s.start_ea, sclass)
        )
        return 0

    def segm_attrs_updated(self, s):
        print(
            "Detected a segment attributes changed for start: 0x%x, perms: 0x%x"
            % (s.start_ea, s.perm)
        )
        return 0

    def segm_moved(self, from_ea, to_ea, size, changed_netmap):
        print("Detected a segment moved from 0x%x to 0x%x" % (from_ea, to_ea))
        return 0

    def byte_patched(self, ea, old_value):
        bytes = ida_bytes.get_wide_byte(ea)
        print("Detected a byte patched: at 0x%x" % (ea))
        return 0

    def sgr_changed(self, start_ea, end_ea, regnum, value, old_value, tag):
        # XXX
        print("Detected sgr_changed()")
        return 0


class MyHexRaysHooks(ida_idp.IDB_Hooks):
    def __init__(self):
        ida_idp.IDB_Hooks.__init__(self)
        print("MyHexRaysHooks init done")
        self._available = None
        self._installed = False
        self._func_ea = ida_idaapi.BADADDR
        self._labels = {}
        self._cmts = {}
        self._iflags = {}
        self._lvar_settings = {}
        self._numforms = {}

    def hook(self):
        if self._available is None:
            if not ida_hexrays.init_hexrays_plugin():
                self._plugin.logger.info("Hex-Rays SDK is not available")
                self._available = False
            else:
                ida_hexrays.install_hexrays_callback(self._hxe_callback)
                self._available = True

        if self._available:
            self._installed = True

    def unhook(self):
        if self._available:
            self._installed = False

    def _hxe_callback(self, event, *_):
        if not self._installed:
            print("HexRays hooks not installed, exiting early")
            return 0

        if event == ida_hexrays.hxe_func_printed:
            ea = ida_kernwin.get_screen_ea()
            func = ida_funcs.get_func(ea)
            if func is None:
                print("func is None, early exit")
                return 0

            if self._func_ea != func.start_ea:
                self._func_ea = func.start_ea
                self._labels = MyHexRaysHooks._get_user_labels(self._func_ea)
                self._cmts = MyHexRaysHooks._get_user_cmts(self._func_ea)
                self._iflags = MyHexRaysHooks._get_user_iflags(self._func_ea)
                self._lvar_settings = MyHexRaysHooks._get_user_lvar_settings(
                    self._func_ea
                )
                self._numforms = MyHexRaysHooks._get_user_numforms(self._func_ea)
            self._print_user_labels(func.start_ea)
            self._print_user_cmts(func.start_ea)
            self._print_user_iflags(func.start_ea)
            self._print_user_lvar_settings(func.start_ea)
            self._print_user_numforms(func.start_ea)
        else:
            print("HexRays: main SKIPPED")
        return 0

    @staticmethod
    def _get_user_labels(ea):
        user_labels = ida_hexrays.restore_user_labels(ea)
        if user_labels is None:
            user_labels = ida_hexrays.user_labels_new()
        labels = []
        it = ida_hexrays.user_labels_begin(user_labels)
        while it != ida_hexrays.user_labels_end(user_labels):
            org_label = ida_hexrays.user_labels_first(it)
            name = ida_hexrays.user_labels_second(it)
            labels.append((org_label, Event.decode(name)))
            it = ida_hexrays.user_labels_next(it)
        ida_hexrays.user_labels_free(user_labels)
        return labels

    def _print_user_labels(self, ea):
        labels = MyHexRaysHooks._get_user_labels(ea)
        if labels != self._labels:
            print("HexRays: Detected a user labels at 0x%x: %s" % (ea, labels))
            self._labels = labels
        else:
            print("HexRays: Detected a user labels SKIPPED")

    @staticmethod
    def _get_user_cmts(ea):
        user_cmts = ida_hexrays.restore_user_cmts(ea)
        if user_cmts is None:
            user_cmts = ida_hexrays.user_cmts_new()
        cmts = []
        it = ida_hexrays.user_cmts_begin(user_cmts)
        while it != ida_hexrays.user_cmts_end(user_cmts):
            tl = ida_hexrays.user_cmts_first(it)
            cmt = ida_hexrays.user_cmts_second(it)
            cmts.append(((tl.ea, tl.itp), cmt))
            it = ida_hexrays.user_cmts_next(it)
        ida_hexrays.user_cmts_free(user_cmts)
        return cmts

    def _print_user_cmts(self, ea):
        cmts = MyHexRaysHooks._get_user_cmts(ea)
        if cmts != self._cmts:
            print("HexRays: Detected a user cmts at 0x%x: %s" % (ea, cmts))
            self._cmts = cmts
        else:
            print("HexRays: Detected a user cmts SKIPPED")

    @staticmethod
    def _get_user_iflags(ea):
        user_iflags = ida_hexrays.restore_user_iflags(ea)
        if user_iflags is None:
            user_iflags = ida_hexrays.user_iflags_new()
        iflags = []
        it = ida_hexrays.user_iflags_begin(user_iflags)
        while it != ida_hexrays.user_iflags_end(user_iflags):
            cl = ida_hexrays.user_iflags_first(it)
            f = ida_hexrays.user_iflags_second(it)

            # FIXME: Temporary while Hex-Rays update their API
            def read_type_sign(obj):
                import ctypes
                import struct

                buf = ctypes.string_at(id(obj), 4)
                return struct.unpack("I", buf)[0]

            f = read_type_sign(f)
            iflags.append(((cl.ea, cl.op), f))
            it = ida_hexrays.user_iflags_next(it)
        ida_hexrays.user_iflags_free(user_iflags)
        return iflags

    def _print_user_iflags(self, ea):
        iflags = MyHexRaysHooks._get_user_iflags(ea)
        if iflags != self._iflags:
            print("HexRays: Detected a user iflags at 0x%x: %s" % (ea, iflags))
            self._iflags = iflags
        else:
            print("HexRays: Detected a user iflags SKIPPED")

    @staticmethod
    def _get_user_lvar_settings(ea):
        dct = {}
        lvinf = ida_hexrays.lvar_uservec_t()
        if ida_hexrays.restore_user_lvar_settings(lvinf, ea):
            dct["lvvec"] = []
            for lv in lvinf.lvvec:
                dct["lvvec"].append(MyHexRaysHooks._get_lvar_saved_info(lv))
            if hasattr(lvinf, "sizes"):
                dct["sizes"] = list(lvinf.sizes)
            dct["lmaps"] = []
            it = ida_hexrays.lvar_mapping_begin(lvinf.lmaps)
            while it != ida_hexrays.lvar_mapping_end(lvinf.lmaps):
                key = ida_hexrays.lvar_mapping_first(it)
                key = MyHexRaysHooks._get_lvar_locator(key)
                val = ida_hexrays.lvar_mapping_second(it)
                val = MyHexRaysHooks._get_lvar_locator(val)
                dct["lmaps"].append((key, val))
                it = ida_hexrays.lvar_mapping_next(it)
            dct["stkoff_delta"] = lvinf.stkoff_delta
            dct["ulv_flags"] = lvinf.ulv_flags
        return dct

    @staticmethod
    def _get_lvar_saved_info(lv):
        return {
            "ll": MyHexRaysHooks._get_lvar_locator(lv.ll),
            "name": lv.name,
            "type": MyHexRaysHooks._get_tinfo(lv.type),
            "cmt": lv.cmt,
            "flags": lv.flags,
        }

    @staticmethod
    def _get_tinfo(type):
        if type.empty():
            return None, None, None

        type, fields, fldcmts = type.serialize()
        return type, fields, fldcmts

    @staticmethod
    def _get_lvar_locator(ll):
        return {
            "location": MyHexRaysHooks._get_vdloc(ll.location),
            "defea": ll.defea,
        }

    @staticmethod
    def _get_vdloc(location):
        return {
            "atype": location.atype(),
            "reg1": location.reg1(),
            "reg2": location.reg2(),
            "stkoff": location.stkoff(),
            "ea": location.get_ea(),
        }

    def _print_user_lvar_settings(self, ea):
        lvar_settings = MyHexRaysHooks._get_user_lvar_settings(ea)
        if lvar_settings != self._lvar_settings:
            print(
                "HexRays: Detected a user lvars settings at 0x%x: %s"
                % (ea, lvar_settings)
            )
            self._lvar_settings = lvar_settings
        else:
            print("HexRays: Detected a user lvars settings SKIPPED")

    @staticmethod
    def _get_user_numforms(ea):
        user_numforms = ida_hexrays.restore_user_numforms(ea)
        if user_numforms is None:
            user_numforms = ida_hexrays.user_numforms_new()
        numforms = []
        it = ida_hexrays.user_numforms_begin(user_numforms)
        while it != ida_hexrays.user_numforms_end(user_numforms):
            ol = ida_hexrays.user_numforms_first(it)
            nf = ida_hexrays.user_numforms_second(it)
            numforms.append(
                (
                    MyHexRaysHooks._get_operand_locator(ol),
                    MyHexRaysHooks._get_number_format(nf),
                )
            )
            it = ida_hexrays.user_numforms_next(it)
        ida_hexrays.user_numforms_free(user_numforms)
        return numforms

    @staticmethod
    def _get_operand_locator(ol):
        return {"ea": ol.ea, "opnum": ol.opnum}

    @staticmethod
    def _get_number_format(nf):
        return {
            "flags": nf.flags,
            "opnum": nf.opnum,
            "props": nf.props,
            "serial": nf.serial,
            "org_nbytes": nf.org_nbytes,
            "type_name": nf.type_name,
        }

    def _print_user_numforms(self, ea):
        numforms = MyHexRaysHooks._get_user_numforms(ea)
        if numforms != self._numforms:
            print("HexRays: Detected a user numforms at 0x%x: %s" % (ea, numforms))
            self._numforms = numforms
        else:
            print("HexRays: Detected a user numforms SKIPPED")


idb_hooks = MyIDBHooks()
idb_hooks.hook()
print("MyIDBHooks installed")

hexrays_hooks = MyHexRaysHooks()
hexrays_hooks.hook()
print("MyHexRaysHooks installed")
