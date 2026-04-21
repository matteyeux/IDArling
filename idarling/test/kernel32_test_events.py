# hardcoded for kernel32.dll
#
# Usage:
# 1. Load kernel32.dll with symbols in IDA
# 2. Enable TRACE level logs on both IDArling IDA plugin and remote server
# 3. Connect to IDArling server from IDA and save IDB before doing anything in IDA
# 4. run IDA script: test_events.py
# 5. check events being sent by IDA plugin / received by server
# 6. Close IDA and re-open previously saved snapshot
# 7. Check replay of events sent by server / received by IDA plugin

import time, ida_hexrays

print("[+] Create nops at 0x78D35379 -> MakeCodeEvent")
create_insn(0x78D35379)
print("[+] Create 3-byte data at 0x78DBDC90 -> MakeDataEvent")
create_data(0x78DBDC90, 1024, 3, -1)
print("[+] Rename at 0x78DBDC90 -> RenamedEvent")
set_name(0x78DBDC90, "TestName", 0)

print("[+] Add an empty function at 0x78DE7B30 and 0x78DF3170 -> FuncAddedEvent")
add_func(0x78DE7B30)
add_func(0x78DF3170)

print("[+] Delete previous function at 0x78DF3170 -> DeletingFuncEvent")
del_func(0x78DF3170)

# XXX - SetFuncStartEvent
# XXX - SetFuncEndEvent
# XXX - FuncTailAppendedEvent
# XXX - FuncTailDeletedEvent
# XXX - TailOwnerChangedEvent

print("[+] Set 2 comments in assembly at 0x78DF3170 and 0x78DF3171 -> CmtChangedEvent")
set_cmt(0x78DF3170, "test comment non repeatable", 0)
set_cmt(0x78DF3171, "test comment repeatable", 1)

print("[+] Set a function comment at 0x78DBB050 -> RangeCmtChangedEvent")
func = ida_funcs.get_func(0x78DBB050)
ida_funcs.set_func_cmt(func, "function comment", 0)

print("[+] Set 2 comments before and after at 0x78DE7B30 -> CmtChangedEvent")
ida_lines.add_extra_cmt(0x78DE7B30, 1, "previous comment")
ida_lines.add_extra_cmt(0x78DE7B30, 0, "next comment")

# XXX - TiChangedEvent
# XXX - LocalTypesChangedEvent
# XXX - OpTypeChangedEvent

print(
    "[+] Change the argument: 0C000000D hexadecimal to decimal at 0x78DBB46A in assembly  -> OpTypeChangedEvent"
)
op_dec(0x78DBB46A, 1)

print("[+] Create an enum -> EnumCreatedEvent")
ida_enum.add_enum(BADADDR, "test_enum_name", 0)
ida_enum.add_enum(BADADDR, "test_enum_name_to_rename", 0)
ida_enum.add_enum(BADADDR, "test_enum_name_to_delete", 0)

print("[+] Delete an enum -> EnumDeletedEvent")
ida_enum.del_enum(ida_enum.get_enum("test_enum_name_to_delete"))

print("[+] Rename an enum -> EnumRenamedEvent")
enum = ida_enum.get_enum("test_enum_name_to_rename")
ida_enum.set_enum_name(enum, "test_enum_renamed")

# XXX - EnumBfChangedEvent
# XXX - EnumCmtChangedEvent

print("[+] Add enum members -> EnumMemberCreatedEvent")
enum = ida_enum.get_enum("test_enum_name")
ida_enum.add_enum_member(enum, "TEST_ENUM_0", 0, -1)
ida_enum.add_enum_member(enum, "TEST_ENUM_0x10", 0x10, -1)
ida_enum.add_enum_member(enum, "TEST_ENUM_0x20_to_delete", 0x20, -1)

print("[+] Delete enum members -> EnumMemberDeletedEvent")
enum = ida_enum.get_enum("test_enum_name")
ida_enum.del_enum_member(enum, 0x20, 0, -1)

print("[+] Create a struct -> StrucCreatedEvent")
ida_struct.add_struc(BADADDR, "test_struct_name", 0)
ida_struct.add_struc(BADADDR, "test_struct_name_to_delete", 0)

print("[+] Delete a struct -> StrucDeletedEvent")
struc = ida_struct.get_struc_id("test_struct_name_to_delete")
ida_struct.del_struc(ida_struct.get_struc(struc))

print("[+] Rename _UNICODE_STRING to _UNICODE_STRING_RENAMED -> StrucRenamedEvent")
struc = ida_struct.get_struc_id("_UNICODE_STRING")
ida_struct.set_struc_name(struc, "_UNICODE_STRING_RENAMED")

# XXX - StrucCmtChangedEvent

# XXX - StrucMemberCreatedEvent
# struc = ida_struct.get_struc_id("test_struct_name")
# sptr = ida_struct.get_struc(struc)
# ida_struct.add_struc_member(sptr, "field_0", 0x0, ida_bytes.qword_flag(), ida_nalt.opinfo_t(), 4)

# XXX - StrucMemberChangedEvent
# XXX - StrucMemberDeletedEvent
# XXX - StrucMemberRenamedEvent
# XXX - ExpandingStrucEvent
# XXX - SegmAddedEvent
# XXX - SegmDeletedEvent
# XXX - SegmStartChangedEvent
# XXX - SegmEndChangedEvent
# XXX - SegmNameChangedEvent
# XXX - SegmClassChangedEvent
# XXX - SegmAttrsUpdatedEvent
# XXX - SegmMoved

print("[+] Undefining string at 0x78DBDCB0 -> UndefinedEvent")
del_items(0x78DBDCB0)

# XXX - BytePatchedEvent
# XXX - SgrChanged

# XXX - UserLabelsEvent

print(
    "[+] Defining 2 comments in HexRays window in function defined at 0x78DBB091 -> UserCmtsEvent"
)
list_comments = [
    ((0x78DBB06A, 74), "one comment in HexRays"),
    ((0x78DBB091, 74), "another comment in HexRays"),
]
cmts = ida_hexrays.user_cmts_new()
for (tl_ea, tl_itp), cmt in list_comments:
    tl = ida_hexrays.treeloc_t()
    tl.ea = tl_ea
    tl.itp = tl_itp
    cmts.insert(tl, ida_hexrays.citem_cmt_t(cmt))
ida_hexrays.save_user_cmts(0x78DBB050, cmts)

# XXX - UserIflagsEvent
# XXX - UserLvarSettingsEvent
# XXX - UserNumformsEvent
