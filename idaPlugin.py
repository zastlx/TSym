#region imports
import ida_idaapi
#endregion imports

class TSymPluginMod(ida_idaapi.plugmod_t):
    def run(self, arg):
        print("Running TSym plugin with argument:", arg)

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