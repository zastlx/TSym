#region imports
import idc
import idaapi
import ida_idaapi
import ida_hexrays
import ida_name
import ida_kernwin
from enum import Enum
from dataclasses import dataclass
from typing import List
from tkinter import Tk
from tkinter.filedialog import askdirectory
#endregion imports

# these can probably be put in a common file
#region utils
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
    return

 # TODO: add parsing for labels and types
#endregion utils

def rename_func_var(func: idaapi.cfuncptr_t, offset: int, name: str):
    args = func.get_lvars()
    if offset >= len(args):
        print(f"Offset {offset} is out of range for function {func.entry_ea}")
        return
    
    ida_hexrays.rename_lvar(func.entry_ea, args[offset].name, name)

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

    def import_symbols(self):
        print("Importing TSym symbols...")
        # TODO: add comments, labels and types support, should we select each file individually? or just the directory?
        file = ida_kernwin.ask_file(0, "*.txt", "Select TSym symbols.txt file")
        if file:
            print(f"Importing symbols from {file}...")
            with open(file, "r") as f:
                data = f.read()
                #region parse symbols
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
                        for defaultName in defaultNamesStart:
                            if arg.name.startswith(defaultName):
                                continue

                        cfunc = idaapi.decompile(symbol.address)
                        rename_func_var(cfunc, i, arg.name)
                #endregion parse symbols  

    # ida has a method for asking for a file, but not for a directory ??
    def ask_directory(self, title):
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