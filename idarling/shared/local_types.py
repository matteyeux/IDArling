# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
import base64
import collections
import pickle
import struct

import ida_pro
import ida_typeinf
import idaapi
import idc

from idarling.shared import forms

fDebug = False
if fDebug:
    import pydevd_pycharm


class TinfoReader(object):
    def __init__(self, tp):
        self.pos = 0
        self.tp = tp

    def read_byte(self):
        (result,) = struct.unpack("<B", self.tp[self.pos : self.pos + 1])
        self.pos += 1
        return result

    def read_string(self, cb):
        ret = self.tp[self.pos : self.pos + cb]
        self.pos += cb
        return ret

    def keep_going(self):
        return self.pos < len(self.tp)


def encode_ordinal_to_string(ordinal):
    enc = []
    # print "encode_ordinal_to_string: ordinal %d"%ordinal
    enc.append(ordinal & 0x7F | 0x40)
    if ordinal > 0x3F:
        bt = ordinal
        bt = bt // 0x40
        enc.append(bt & 0x7F | 0x80)
        while bt > 0x7F:
            bt = bt // 0x80
            enc.append(bt & 0x7F | 0x80)
    # stemp = struct.pack("B",len(enc)+2) + "#"
    stemp = []
    stemp.append(len(enc) + 2)
    stemp.append(ord("#"))
    # for i in range(0,len(enc)):
    #     stemp = stemp + struct.pack("B",enc.pop(-1))
    # print stemp
    # print enc
    enc.reverse()
    # print enc
    stemp = stemp + enc
    return stemp


def decode_ordinal_string(enc):
    if enc[1] == ord("#"):
        ord_num = 0
        i = 0
        fEnd = 0
        str_len = struct.unpack("B", enc[0:1])[0] - 2
        # print len
        for ch in enc[2:]:
            if ch == 0:
                return 0
            ord_num = ord_num * 0x40
            if ch & 0x80 != 0:
                ord_num = ord_num * 2
                ch = ch & 0x7F
            else:
                ch = ch & 0x3F
                fEnd = 1
            ord_num = ord_num | ch
            i = i + 1
            if fEnd > 0 or i >= str_len:
                break
        return ord_num
    return 0


class LocalType(object):
    # Flags = {
    #     "struct":1,
    #     "enum":2,
    #     "other":4,
    #     "standard":8
    # }

    def __init__(
        self,
        name=b"",
        TypeString=b"",
        TypeFields=b"",
        cmt=b"",
        fieldcmts=b"",
        sclass=0,
        parsedList=None,
        depends=None,
        isStandard=False,
    ):
        self.TypeString = TypeString
        self.TypeFields = TypeFields
        self.cmt = cmt
        self.fieldcmts = (
            fieldcmts if type(fieldcmts) == bytes else fieldcmts.encode("utf-8")
        )
        self.sclass = sclass
        self.name = name
        self.parsedList = [] if parsedList is None else parsedList
        self.depends = [] if depends is None else depends
        self.depends_ordinals = []
        self.flags = 8 if isStandard else 0
        # print "Type string: %s"%self.TypeString.encode("HEX")
        if self.TypeString != b"":
            self.parsedList = self.ParseTypeString(self.TypeString)
        if self.parsedList is not None and self.TypeString == b"":
            self.TypeString = self.GetTypeString()
        if self.TypeString != b"":
            if self.is_su():
                self.flags |= 1
            elif self.is_enum():
                self.flags |= 2
            elif self.isnt_sue():
                self.flags |= 4

    # def __init__(self, idx):
    #     self.name = None
    #     self.parsedList = []
    #     self.TypeString = None
    #     self.TypeFields = None
    #     self.cmt = None
    #     self.fieldcmts = None
    #     self.sclass = None
    #     self.depends = []

    @staticmethod
    def find_type_by_name(name):
        my_ti = idaapi.get_idati()
        ordinal = idaapi.get_type_ordinal(my_ti, name)

    def GetTypeString(self):
        ti = idaapi.get_idati()
        # print "GetTypeString: name %s"%self.name
        the_bytes = []
        for thing in self.parsedList:
            if type(thing) == int:  # if it's a byte, just put it back in
                the_bytes.append(thing)
            elif len(thing) == 1:
                if list(thing.keys())[0] == "local_type":
                    the_bytes.append(ord("="))  # a type starts with =
                # print type(thing["local_type"]),thing["local_type"]
                ordinal = idaapi.get_type_ordinal(
                    ti, list(thing.values())[0]
                )  # get the ordinal of the Local Type based on its name
                if ordinal > 0:
                    the_bytes = the_bytes + encode_ordinal_to_string(ordinal)
                else:
                    raise NameError("Depends local type not in IDB")
            else:
                raise NameError("Wrong depend record for type: %s!" % self.name)
        packed = struct.pack("%dB" % len(the_bytes), *the_bytes)
        return packed

    def ParseTypeString(self, type_string):
        if fDebug:
            pydevd_pycharm.settrace(
                "127.0.0.1",
                port=31337,
                stdoutToServer=True,
                stderrToServer=True,
                suspend=False,
            )
        tp = TinfoReader(type_string)
        # print idc_print_type(type_, fields, "fun_name", 0)
        # print type_.encode("string_escape")
        output = []
        """
        Attempt to copy the tinfo from a location, replacing any Local Types with our own representation of them.
        Pass all other bytes through as-is.
        """
        while tp.keep_going():
            a_byte = tp.read_byte()
            unwritten_bytes = [a_byte]
            if a_byte == ord("=") and tp.pos < len(tp.tp):  # a type begins
                ordinal_length = tp.read_byte()
                if (
                    tp.pos < len(tp.tp)
                    and len(tp.tp) - (tp.pos + ordinal_length - 1) >= 0
                ):
                    number_marker = tp.read_byte()
                    if number_marker == ord(
                        "#"
                    ):  # this is a Local Type referred to by its ordinal
                        ordinal = decode_ordinal_string(
                            struct.pack("B", ordinal_length)
                            + b"#"
                            + tp.read_string(ordinal_length - 2)
                        )
                        t = idc.get_numbered_type_name(ordinal)
                        output.append({"local_type": t})
                        if t not in self.depends:
                            self.depends.append(t)
                            self.depends_ordinals.append(ordinal)
                        continue
                    else:
                        unwritten_bytes.append(ordinal_length)
                        unwritten_bytes.append(number_marker)
                else:
                    unwritten_bytes.append(ordinal_length)
            elif a_byte == ord("#") and (
                (len(output) >= 4 and output[-4:-1] == [0x0A, 0x0D, 0x01])
                or (len(output) >= 3 and output[-3:-1] == [0x0D, 0x01])
            ):
                ordinal_length = output[-1]
                output.pop(-1)
                ordinal = decode_ordinal_string(
                    struct.pack("B", ordinal_length)
                    + b"#"
                    + tp.read_string(ordinal_length - 2)
                )
                t = idc.get_numbered_type_name(ordinal)
                output.append({"rare_local_type": t})
                if t not in self.depends:
                    self.depends.append(t)
                    self.depends_ordinals.append(ordinal)
                continue

            output += unwritten_bytes  # put all the bytes we didn't consume into the output as-is

        return output

    def to_dict(self):
        ser_dic = collections.OrderedDict()
        ser_dic["name"] = self.name
        ser_dic["TypeString"] = base64.b64encode(self.TypeString)
        ser_dic["TypeFields"] = base64.b64encode(self.TypeFields)
        ser_dic["cmt"] = base64.b64encode(self.cmt)
        ser_dic["fieldcmts"] = base64.b64encode(self.fieldcmts)
        ser_dic["sclass"] = base64.b64encode(pickle.dumps(self.sclass))
        ser_dic["parsedList"] = base64.b64encode(pickle.dumps(self.parsedList))
        ser_dic["depends"] = base64.b64encode(pickle.dumps(self.depends))
        ser_dic["depends_ordinals"] = base64.b64encode(
            pickle.dumps(self.depends_ordinals)
        )
        ser_dic["flags"] = self.flags
        return ser_dic

    def to_iter(self):
        return (
            self.name,
            base64.b64encode(self.TypeString),
            base64.b64encode(self.TypeFields),
            base64.b64encode(self.cmt),
            base64.b64encode(self.fieldcmts),
            base64.b64encode(pickle.dumps(self.sclass)),
            base64.b64encode(pickle.dumps(self.parsedList)),
            base64.b64encode(pickle.dumps(self.depends)),
            base64.b64encode(pickle.dumps(self.depends_ordinals)),
            self.flags,
        )

    def from_dict(self, ser_dic):
        self.name = ser_dic["name"]
        self.TypeString = base64.b64decode(ser_dic["TypeString"])
        # print "from_dict; TypeString = %s"%self.TypeString
        self.TypeFields = base64.b64decode(ser_dic["TypeFields"])
        self.cmt = base64.b64decode(ser_dic["cmt"])
        self.fieldcmts = base64.b64decode(ser_dic["fieldcmts"])
        self.sclass = int(ser_dic["sclass"])
        self.parsedList = ser_dic["parsedList"]
        self.depends = ser_dic["depends"]
        self.depends_ordinals = ser_dic["depends_ordinals"]
        # self.sclass = ctypes.c_ulong(self.sclass)
        self.flags = ser_dic["flags"]
        return self

    def print_type(self):
        ret = idaapi.idc_print_type(
            self.GetTypeString(),
            self.TypeFields,
            self.name,
            idaapi.PRTYPE_MULTI | idaapi.PRTYPE_TYPE,
        )
        if ret is None:
            return ""
        i = 0
        ret = ret.strip()
        return ret

    def is_standard(self):
        return self.flags & 8 == 8

    def isEqual(self, t):
        if (
            t
            and self.parsedList == t.parsedList
            and self.TypeFields == t.TypeFields
            and self.name == t.name
        ):
            return True
        return False

    def __eq__(self, other):
        if isinstance(other, LocalType):
            return self.isEqual(other)
        return False

    def to_tuple(self):
        return self.name, self.parsedList, self.TypeFields.decode()

    def is_complex(self):
        return self.TypeString[0] & idaapi.TYPE_BASE_MASK == idaapi.BT_COMPLEX

    def is_typedef(self):
        return self.TypeString[0] & idaapi.TYPE_FULL_MASK == idaapi.BTF_TYPEDEF

    def is_sue(self):
        return self.is_complex() and not self.is_typedef()

    def isnt_sue(self):
        return not self.is_sue()

    def is_su(self):
        return self.is_complex() and not self.is_typedef() and not self.is_enum()

    def is_paf(self):
        t = self.TypeString[0] & idaapi.TYPE_BASE_MASK
        return (t >= idaapi.BT_PTR) & (t <= idaapi.BT_FUNC)

    def is_func(self):
        return self.TypeString[0] & idaapi.TYPE_BASE_MASK == idaapi.BT_FUNC

    def is_struct(self):
        return self.TypeString[0] & idaapi.TYPE_FULL_MASK == idaapi.BTF_STRUCT

    def is_union(self):
        return self.TypeString[0] & idaapi.TYPE_FULL_MASK == idaapi.BTF_UNION

    def is_enum(self):
        return self.TypeString[0] & idaapi.TYPE_FULL_MASK == idaapi.BTF_ENUM

    def is_ptr(self):
        return self.TypeString[0] & idaapi.TYPE_FULL_MASK == idaapi.BT_PTR

    @staticmethod
    def is_complex_static(TypeString):
        return TypeString[0] & idaapi.TYPE_BASE_MASK == idaapi.BT_COMPLEX

    @staticmethod
    def is_typedef_static(TypeString):
        return TypeString[0] & idaapi.TYPE_FULL_MASK == idaapi.BTF_TYPEDEF

    @staticmethod
    def is_sue_static(TypeString):
        return LocalType.is_complex_static(
            TypeString
        ) and not LocalType.is_typedef_static(TypeString)

    @staticmethod
    def isnt_sue_static(TypeString):
        return not LocalType.is_sue_static(TypeString)

    @staticmethod
    def is_su_static(TypeString):
        return (
            LocalType.is_complex_static(TypeString)
            and not LocalType.is_typedef_static(TypeString)
            and not LocalType.is_enum_static(TypeString)
        )

    @staticmethod
    def is_paf_static(TypeString):
        t = TypeString[0] & idaapi.TYPE_BASE_MASK
        return (t >= idaapi.BT_PTR) & (t <= idaapi.BT_FUNC)

    @staticmethod
    def is_func_static(TypeString):
        return TypeString[0] & idaapi.TYPE_BASE_MASK == idaapi.BT_FUNC

    @staticmethod
    def is_struct_static(TypeString):
        return TypeString[0] & idaapi.TYPE_FULL_MASK == idaapi.BTF_STRUCT

    @staticmethod
    def is_union_static(TypeString):
        return TypeString[0] & idaapi.TYPE_FULL_MASK == idaapi.BTF_UNION

    @staticmethod
    def is_enum_static(TypeString):
        return TypeString[0] & idaapi.TYPE_FULL_MASK == idaapi.BTF_ENUM


def ParseTypeString(type_string):
    if fDebug:
        pydevd_pycharm.settrace(
            "127.0.0.1",
            port=31337,
            stdoutToServer=True,
            stderrToServer=True,
            suspend=False,
        )
    tp = TinfoReader(type_string)
    # print idc_print_type(type_, fields, "fun_name", 0)
    # print type_.encode("string_escape")
    output = []
    """
    Attempt to copy the tinfo from a location, replacing any Local Types with our own representation of them.
    Pass all other bytes through as-is.
    """
    while tp.keep_going():
        a_byte = tp.read_byte()
        unwritten_bytes = [a_byte]
        if a_byte == ord("=") and tp.pos < len(tp.tp):  # a type begins
            ordinal_length = tp.read_byte()
            if tp.pos < len(tp.tp) and len(tp.tp) - (tp.pos + ordinal_length - 1) >= 0:
                number_marker = tp.read_byte()
                if number_marker == ord(
                    "#"
                ):  # this is a Local Type referred to by its ordinal
                    ordinal = decode_ordinal_string(
                        struct.pack("B", ordinal_length)
                        + b"#"
                        + tp.read_string(ordinal_length - 2)
                    )
                    t = idc.get_numbered_type_name(ordinal)
                    output.append({"local_type": t})
                    # if t not in self.depends:
                    #     self.depends.append(t)
                    #     self.depends_ordinals.append(ordinal)
                    continue
                else:
                    unwritten_bytes.append(ordinal_length)
                    unwritten_bytes.append(number_marker)
            else:
                unwritten_bytes.append(ordinal_length)
        elif a_byte == ord("#") and (
            (len(output) >= 4 and output[-4:-1] == [0x0A, 0x0D, 0x01])
            or (len(output) >= 3 and output[-3:-1] == [0x0D, 0x01])
        ):
            ordinal_length = output[-1]
            output.pop(-1)
            ordinal = decode_ordinal_string(
                struct.pack("B", ordinal_length)
                + b"#"
                + tp.read_string(ordinal_length - 2)
            )
            t = idc.get_numbered_type_name(ordinal)
            output.append({"rare_local_type": t})
            # if t not in self.depends:
            #     self.depends.append(t)
            #     self.depends_ordinals.append(ordinal)
            continue

        output += (
            unwritten_bytes  # put all the bytes we didn't consume into the output as-is
        )

    return output


def GetTypeString(parsedList, name=""):
    ti = idaapi.get_idati()
    # print "GetTypeString: name %s"%self.name
    the_bytes = []
    for thing in parsedList:
        if type(thing) == int:  # if it's a byte, just put it back in
            the_bytes.append(thing)
        elif len(thing) == 1:
            if list(thing.keys())[0] == "local_type":
                the_bytes.append(ord("="))  # a type starts with =
            # print type(thing["local_type"]),thing["local_type"]
            ordinal = idaapi.get_type_ordinal(
                ti, list(thing.values())[0]
            )  # get the ordinal of the Local Type based on its name
            if ordinal > 0:
                the_bytes = the_bytes + encode_ordinal_to_string(ordinal)
            else:
                raise NameError("Depends local type not in IDB")
        else:
            raise NameError("Wrong depend record for type: %s!" % name)
    packed = struct.pack("%dB" % len(the_bytes), *the_bytes)
    return packed


def ImportLocalType(idx):
    name = ida_typeinf.get_numbered_type_name(ida_typeinf.get_idati(), idx)
    # todo: doing something with empty and error types
    ret = ida_typeinf.get_numbered_type(ida_typeinf.get_idati(), idx)
    if ret is not None:
        typ_type, typ_fields, typ_cmt, typ_fieldcmts, typ_sclass = ret
        if typ_type is None:
            typ_type = b""
        if typ_fields is None:
            typ_fields = b""
        if typ_cmt is None:
            typ_cmt = b""
        if typ_fieldcmts is None:
            typ_fieldcmts = b""
        return LocalType(name, typ_type, typ_fields, typ_cmt, typ_fieldcmts, typ_sclass)
    return None


def ImportNamedLocalType(idx):
    name = ida_typeinf.get_numbered_type_name(ida_typeinf.get_idati(), idx)
    if name:
        # todo: doing something with empty and error types
        ret = ida_typeinf.get_numbered_type(ida_typeinf.get_idati(), idx)
        if ret is not None:
            typ_type, typ_fields, typ_cmt, typ_fieldcmts, typ_sclass = ret
            if typ_type is None:
                typ_type = b""
            if typ_fields is None:
                typ_fields = b""
            if typ_cmt is None:
                typ_cmt = b""
            if typ_fieldcmts is None:
                typ_fieldcmts = b""
            return LocalType(
                name, typ_type, typ_fields, typ_cmt, typ_fieldcmts, typ_sclass
            )
    return None


def DuplicateResolver(t1, t2, fToStorage=False):
    f = forms.DublicateResolverUI(t1.print_type(), t2.print_type(), fToStorage)
    while True:
        f.Go()
        if f.sel == 1:
            return t1
        elif f.sel == 2:
            return t2
        else:
            r = idc.parse_decl(f.selText, 0x008E)
            if r is not None:
                return LocalType(r[0], r[1], r[2])


def getTypeOrdinal(name):
    my_ti = ida_typeinf.get_idati()
    return ida_typeinf.get_type_ordinal(my_ti, name)


def InsertType(type_obj, fReplace=False):
    # print("Insert type %s." % type_obj.name)
    wrapperTypeString = b"\x0d\x01\x01"
    if getTypeOrdinal(type_obj.name) != 0:
        idx = getTypeOrdinal(type_obj.name)
        t = ImportLocalType(idx)
        if (t.TypeFields is None or t.TypeFields == "") and t.is_sue():
            fReplace = True
        if t.isEqual(type_obj) or type_obj.TypeString == wrapperTypeString:
            return 1
        if not fReplace:
            type_obj = DuplicateResolver(t, type_obj, False)
    else:
        idx = ida_typeinf.alloc_type_ordinals(idaapi.get_idati(), 1)
    tif = ida_typeinf.tinfo_t()
    ret = tif.deserialize(
        ida_typeinf.get_idati(),
        type_obj.GetTypeString(),
        type_obj.TypeFields,
        type_obj.fieldcmts,
    )
    if not ret:
        idaapi.warning(
            "Error on tinfo deserilization, type name = %s, ret = %d"
            % (type_obj.name, ret)
        )
        ret = -1
    else:
        ret = tif.set_numbered_type(idaapi.get_idati(), idx, 0x4, type_obj.name)
    del tif
    # ret = idaapi.set_numbered_type(
    #     my_ti,
    #     idx,
    #     0x4,
    #     type_obj.name,
    #     type_obj.GetTypeString(),
    #     type_obj.TypeFields,
    #     type_obj.cmt,
    #     type_obj.fieldcmts
    # )
    # print "Insert type %s. ret = %d"%(type_obj.name,ret)
    if (ida_pro.IDA_SDK_VERSION < 700 and ret != 1) or (
        ida_pro.IDA_SDK_VERSION >= 700 and ret != 0
    ):
        print("bad insert: %s; ret = %d" % (type_obj.name, ret))
    return ret


def checkExistence(name_list, target_list):
    for name in name_list:
        if name not in target_list:
            return False
    return True


def addTypeWrapper(name):
    wrapperTypeString = b"\x0d\x01\x01"
    return LocalType(name, wrapperTypeString)


def resolveDependencies(startList):
    toResolve = startList
    toResolveNames = []
    # print "resolveDependencies: startList", startList
    prev_len = -1
    for t in toResolve:
        toResolveNames.append(t.name)
    sortedList = []
    # print "resolveDependencies: toResolveNames", toResolve
    # toResolveNames = toResolve
    # toResolve = self.getFromStorage(toResolve)
    prev_len = len(toResolve)
    sortedListNames = []

    while len(toResolve) > 0:
        for t in toResolve:
            if len(t.depends) == 0:
                sortedList.append(t)
                toResolve.remove(t)
                sortedListNames.append(t.name)
                toResolveNames.remove(t.name)
            else:
                if checkExistence(t.depends, sortedListNames):
                    sortedList.append(t)
                    toResolve.remove(t)
                    sortedListNames.append(t.name)
                    toResolveNames.remove(t.name)
        if prev_len == len(toResolve):
            for t in toResolve:
                for name in t.depends:
                    if checkExistence([name], sortedListNames):
                        continue
                    elif checkExistence([name], toResolveNames):
                        sortedList.append(addTypeWrapper(name))
                        sortedListNames.append(name)
                        continue
                    else:
                        raise NameError(
                            "resolveDependencies: Unresolved type dependencies %s"
                            % name
                        )
        prev_len = len(toResolve)
    return sortedList
