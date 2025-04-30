#region imports
import idc
import idaapi
import ida_idaapi
import ida_hexrays
import ida_name
import ida_kernwin
import os
import re
from enum import Enum
from dataclasses import dataclass
from typing import List
from tkinter import Tk
from tkinter.filedialog import askdirectory
#endregion

# these can probably be put in a common file
#region TSym parsing utils
class CallingConvention(Enum):
    CDECL     = "__cdecl"
    STDCALL   = "__stdcall"
    FASTCALL  = "__fastcall"
    THISCALL  = "__thiscall"
    VECTORCALL= "__vectorcall"
    UNKNOWN   = "unknown"

@dataclass
class Argument:
    name: str
    type: str

@dataclass
class Symbol:
    address: int
    return_type: str
    call_convention: CallingConvention
    namespaces: List[str]
    name: str
    args: List[Argument]
    has_var_args: bool

def parse_symbols(data: str) -> List[Symbol]:
    lines = data.splitlines()
    if not lines:
        return []
    # skip first line with version info
    raw_symbols = "\n".join(lines[1:]).strip().splitlines()

    symbols: List[Symbol] = []
    for line_num, line in enumerate(raw_symbols, start=1):
        parts = line.split(";")
        lenParts = len(parts)
        cur = 0

        try:
            address = int(parts[cur], 16)
        except:
            print(f"Line {line_num}: Invalid address: {parts[cur]}")
            continue
        cur += 1

        try:
            return_type = parts[cur]
        except:
            print(f"Line {line_num}: Missing return type: {parts[cur]}")
            continue
        cur += 1

        try:
            cc_raw = parts[cur]
            call_convention = CallingConvention(cc_raw)
        except:
            print(f"Line {line_num}: Invalid calling convention: {parts[cur]}")
            continue
        cur += 1

        try:
            nmsp_size = int(parts[cur])
        except:
            print(f"Line {line_num}: Invalid namespace size: {parts[cur]}")
            continue
        cur += 1

        namespaces: List[str] = []
        for _ in range(nmsp_size):
            if cur < lenParts:
                namespaces.append(parts[cur])
                cur += 1
            else:
                print(f"Line {line_num}: Namespace entry missing: {parts[cur]}")
                break

        if cur < lenParts:
            name = parts[cur]
        else:
            print(f"Line {line_num}: Missing symbol name: {parts[cur]}")
            continue
        cur += 1

        try:
            args_size = int(parts[cur])
        except:
            print(f"Line {line_num}: Invalid args size: {parts[cur]}")
            continue
        cur += 1

        args: List[Argument] = []
        for _ in range(args_size):
            if cur + 1 < lenParts:
                arg_name = parts[cur]
                arg_type = parts[cur + 1]
                args.append(Argument(name=arg_name, type=arg_type))
                cur += 2
            else:
                print(f"Line {line_num}: Incomplete argument entry: {parts[cur]}")
                continue

        has_var_args = parts[cur].strip().lower() == "true"

        symbols.append(
            Symbol(
                address=address,
                return_type=return_type,
                call_convention=call_convention,
                namespaces=namespaces,
                name=name,
                args=args,
                has_var_args=has_var_args
            )
        )

    return symbols

@dataclass
class Comment:
    address: int
    comment: str
    type: int

#address;string;type
def parse_comments(data: str):
    lines = data.splitlines()
    if not lines:
        return []
    # skip first line with version info
    raw_symbols = "\n".join(lines[1:]).strip().splitlines()

    comments: List[Comment] = []
    for line_num, line in enumerate(raw_symbols, start=1):
        parts = line.split(";")
        cur = 0

        try:
            address = int(parts[cur], 16)
        except:
            print(f"Line {line_num}: Invalid address: {parts[cur]}")
            continue
        cur += 1

        try:
            comment = parts[cur]
        except:
            print(f"Line {line_num}: Missing comment: {parts[cur]}")
            continue
        cur += 1

        try:
            type = int(parts[cur])
        except:
            print(f"Line {line_num}: Invalid type: {parts[cur]}")
            continue

        comments.append(
            Comment(
                address=address,
                comment=comment,
                type=type
            )
        )
    return comments

 # TODO: add parsing for labels
#endregion

#region utils
def parse_helper(data: str, isName: bool = False) -> str:
    regex_rules = [
        (r'//.*', ''), # single line comments
        (r'/\*.*?\*/', '', re.DOTALL), # multi line comments
        (r'public', ''), # access modifiers
        (r'protected', ''),
        (r'private', ''),
        (r':\s+(public)?uint8_t (\*(\s+))+', ""), # https://github.com/DexrnZacAttack/MCXB1-Syms/blob/a4d1aa8a9d8b0a062cda36ef95c0424bec1360c5/types/Minecraft/Classes/FUI/RenderNode/fuiRenderNodeEditText.h#L2
        (r':\s+(public)?uint63_t ', ""), # https://github.com/DexrnZacAttack/MCXB1-Syms/blob/a4d1aa8a9d8b0a062cda36ef95c0424bec1360c5/types/Minecraft/Enums/C4JStorage/ESaveIncompleteType.h#L1
        (r'::', '__'), # replace :: with __
        (r' \*[0-9]+ ', ' '), # "int *64 entry" to "int entry" to adhere with c style syntax
        (r'ulonglong', "unsigned long long"), # adhere to c syntax
        (r'longlong', "long long"),
        (r'pointer[0-9]*', 'uint64_t'), # not 100% sure what the "pointer" type is in ghidra
        (r'pointer', 'uint64_t'),
        (r'[<>]', '__'), # ida doesnt like <>. any other ideas for this?
        (r'\b(?P<base>[\w:<>]+)\s*\[(?P<size>\d+)\]\s*(?P<name>\w+)\b', r'\g<base> \g<name>[\g<size>]'), # "wchar_t[8] name" to "wchar_t name[8]" to adhere with c style syntax
        (r'\(', '_'),
        (r'\)', '_'),
        (r'Item\*', "Item_"), # https://github.com/DexrnZacAttack/MCXB1-Syms/blob/a4d1aa8a9d8b0a062cda36ef95c0424bec1360c5/types/Minecraft/Classes/IdMapper%253Cclass_Item%252A___ptr64%253E.h#L1
        (r'Variant\*', "Variant_"), # https://github.com/DexrnZacAttack/MCXB1-Syms/blob/a4d1aa8a9d8b0a062cda36ef95c0424bec1360c5/types/Minecraft/Classes/TypedBoxed/TypedBoxed%253Cclass_PlanksBlock/Variant%252A___ptr64%253E.h#L2
        (r'struct struct', "struct _struct"), # https://github.com/DexrnZacAttack/MCXB1-Syms/blob/a4d1aa8a9d8b0a062cda36ef95c0424bec1360c5/types/Minecraft/Classes/struct.h#L1
        (r'enum enum', "enum _enum"), # https://github.com/DexrnZacAttack/MCXB1-Syms/blob/a4d1aa8a9d8b0a062cda36ef95c0424bec1360c5/types/Minecraft/Enums/enum.h#L1
        (r'namespace', '_namespace'), # https://github.com/DexrnZacAttack/MCXB1-Syms/blob/a4d1aa8a9d8b0a062cda36ef95c0424bec1360c5/types/Minecraft/Classes/ResourceLocation.h#L12
        (r'}', '};'), # colons at the end of defs
    ]
    name_only_rules = [
        (r'struct', '_struct'),
        (r'union', '_union'),
        (r'enum', '_enum'),
        (r':.+', ''), # remove inheritance, will be added when we properly parse the types
        (r'\*', ''),
        (r',', '_'),
    ]
    badChars = ["~", "`", "!", "^"]

    for pattern, repl, *f in regex_rules:
        flags = f[0] if f else 0
        data = re.sub(pattern, repl, data, flags=flags)
    
    if isName:
        for pattern, repl, *f in name_only_rules:
            flags = f[0] if f else 0
            data = re.sub(pattern, repl, data, flags=flags)
    
    for badChar in badChars:
        data = data.replace(badChar, "")

    if "enum" in data:
        data = re.sub(r'(?<!\});', ',', data)
    
    return data

def rename_func_var(func: idaapi.cfuncptr_t, offset: int, name: str):
    args = func.get_lvars()
    if offset >= len(args):
        print(f"Offset {offset} is out of range for function {func.entry_ea}")
        return
    
    ida_hexrays.rename_lvar(func.entry_ea, args[offset].name, name)

def readDirRecusrive(dir: str):
    out = []
    for files in os.listdir(dir):
        if os.path.isdir(os.path.join(dir, files)):
            out += readDirRecusrive(os.path.join(dir, files))
        else:
            if files.endswith(".h"):
                out.append(os.path.join(dir, files).replace("\\", "/"))
    return out

@dataclass
class Struct:
    type: str
    data: str

def getStructNames(data: str) -> List[Struct]:
    out: List[Struct] = []
    structNames = re.findall(r'struct (.+) {', data)
    unionNames = re.findall(r'union (.+) {', data)
    enumNames = re.findall(r'enum (.+) {', data)
    typeDefs = re.findall(r'typedef (\w+) ', data)
    
    if structNames:
        for structName in structNames:
            out.append(Struct(type="struct", data=parse_helper(structName, True)))
    if unionNames:
        for unionName in unionNames:
            out.append(Struct(type="union", data=parse_helper(unionName, True)))
    if enumNames:
        for enumName in enumNames:
            out.append(Struct(type="enum", data=parse_helper(enumName, True)))
    if typeDefs:
        for typedefName in typeDefs:
            out.append(Struct(type="typedef", data=parse_helper(typedefName, True)))
    

    return out
#endregion

#region import/export functions
def import_symbols(file: str):
    print(f"Importing symbols from {file}...")
    with open(file, "r") as f:
        data = f.read()
        symbols = parse_symbols(data)
        for symbol in symbols:
            if symbol.name.startswith("FUN_") or symbol.name.startswith("thunk_FUN_") or symbol.name.startswith("sub_"):
                continue

            badChars = ["~", "`", ",", "<", ">", "'", "\"", "*", "=", "!", "^"]
            name = symbol.name
            namespaces = "::".join([ns for ns in symbol.namespaces if ns != "Global"])

            for badChar in badChars:
                namespaces = namespaces.replace(badChar, "_")
                name = name.replace(badChar, "_")

            if namespaces:
                print(f"Importing symbol: {namespaces}::{name} at address {hex(symbol.address)}")
                idc.set_name(symbol.address, f"{namespaces}::{name}", ida_name.SN_FORCE)
            else:
                print(f"Importing symbol: {name} at address {hex(symbol.address)}")
                idc.set_name(symbol.address, name, ida_name.SN_FORCE)
            
            for i, arg in enumerate(symbol.args):
                defaultNamesStart = ["arg", "var", "unk", "dword", "byte"]
                if any(arg.name.startswith(default) for default in defaultNamesStart):
                    continue

                cfunc = idaapi.decompile(symbol.address)
                if cfunc == None:
                    print(f"Failed to decompile function at {hex(symbol.address)}")
                    continue

                rename_func_var(cfunc, i, arg.name)

def import_structs(mainDir: str):
    print(f"Importing structs from {mainDir}...")
    parsed = []
    # caused by https://github.com/DexrnZacAttack/TSym/issues/1
    ignore = ["char[0].h", "char[1].h", "char[2].h", "uchar[8].h", "uchar[1].h", "wchar_t[8].h", "wchar_t[0].h", "ulonglong[2].h", "ulonglong[1].h", "undefined[1].h", "undefined[2].h", "undefined[4].h", "undefined[8].h", "undefined[16].h", "undefined.h", "wchar_t.h", "char.h", "uchar.h", "byte.h", "word.h", "dword.h", "qword.h", "uint8_t.h", "uint16_t.h", "uint32_t.h", "uint64_t.h", "int8_t.h", "int16_t.h", "int32_t.h", "int64_t.h", "ulong.h", "long.h", "ushort.h", "short.h", "uint.h", "int.h", "bool.h", "float.h", "double.h", "uint32.h"] 
    # ghidra uses this when it doesn't know the type
    undefined_to_uint = {
        "undefined": "uint8_t",
        "undefined1": "uint8_t",
        "undefined2": "uint16_t",
        "undefined3": "uint32_t",
        "undefined4": "uint32_t",
        "undefined5": "uint64_t",
        "undefined6": "uint64_t",
        "undefined7": "uint64_t",
        "undefined8": "uint64_t",
    }

    def parse_type(dir: str):
        if any(dir.lower().endswith(ign) for ign in ignore) or "Other" in dir:
            return
        dir = re.sub(r'\[.*?\]', '', dir) # "Other/std/shared_ptr%3CMultiplayerLocalPlayer%3E[4].h" -> "Other/std/shared_ptr%3CMultiplayerLocalPlayer%3E.h"
        dir = re.sub(r'%3A%3A', "/", dir) # fixes a few import strings

        if dir in parsed or  "/functions/" in dir or any(dir.endswith(ign) for ign in ignore):
            return
        
        parsed.append(dir)
    
        with open(dir, "r") as f:
            data = f.read()

            for undefined_type, uint_type in undefined_to_uint.items():
                data = re.sub(re.escape(undefined_type + " "), uint_type + " ", data)
            data = re.sub(r'undefined[0-9]*', "uint64_t", data)
    
            data = re.sub(r'dword', "uint32_t", data) # ida doesnt support dword in structs
            
            data = parse_helper(data)

            imports = [] 
            for line in data.splitlines():
                if line.startswith("#include"):
                    # match inside quotes aka imported file
                    imports.append(mainDir + "/" + re.search(r'\"(.+)\"', line).group(1))
                    data = re.sub(r'#include \"(.+)\"', "", data)
                
            if len(imports) > 0:
                for imported in imports:
                    parse_type(imported)
            
            idaapi.parse_decls(None, data, None, idaapi.PT_SIL)
            

    files = readDirRecusrive(mainDir)
    
    # avoid circular dependencies by pre-defining all structs and unions as empty
    deps = []
    for file in files:
        if "Other" in file and not "std" in file: # a lot of wack unneeded stuff in Other that would of required a lot of work to parse, all of the actual important types are included
            continue

        with open(file, "r") as f:
            deps += getStructNames(f.read())
    
    depStr = ""
    for dep in deps:
        if dep.type == "typedef":
            depStr += f"typedef {dep.data};\n"
            continue

        depStr += f"{dep.type} {dep.data} {{}};\n"

    idaapi.parse_decls(None, depStr, None, idaapi.PT_SIL)

    for file in files:
        parse_type(file)
#endregion

class TSymPluginMod(ida_idaapi.plugmod_t):
    def run(self, arg):
        option = ida_kernwin.ask_buttons("Export symbols", "Import symbols", "Cancel", 1, "Do you want to export or import TSym symbols?")
        if option == 1:
            self.export_symbols()
        elif option == 0:
            self.import_symbols()

    def export_symbols(self):
        print("Exporting TSym symbols...")
        directory = self.ask_directory("Select folder to export symbols")
        if directory:
            print(f"Exporting symbols to {directory}...")
            # TODO: implement export logic

    # TODO: add comments and labels, should we select each file individually? or just the directory?
    def import_symbols(self):
        print("Importing TSym symbols...")
        ida_kernwin.info("Select the symbols.txt file")
        file = ida_kernwin.ask_file(0, "*.txt", "Select TSym symbols.txt file")
        if file:
            import_symbols(file)
        else:
            ida_kernwin.msg("No file selected")
            
        ida_kernwin.info("Select folder the folder containing the types (.h files)")
        mainDir = self.ask_directory("Select folder to import types")
        if mainDir:
            import_structs(mainDir)
        else:
            ida_kernwin.msg("No folder selected")
    
    # ida has a method for asking for a file, but not for a directory ??
    def ask_directory(self, title: str):
        root = Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        directory = askdirectory(title=title)
        root.destroy()
        return directory

class TSymPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    comment = "A plugin to export and import TSym symbols"
    help = "Export and import TSym symbols"
    wanted_name = "TSym"
    wanted_hotkey = "Ctrl-Shift-T"

    def init(self):
        return TSymPluginMod()

def PLUGIN_ENTRY():
    return TSymPlugin()
