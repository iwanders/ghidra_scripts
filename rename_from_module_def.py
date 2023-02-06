# Rename ordinals based on module .def file. Only replaces un-renamed "Ordinal_#" to the EXPORT ones from the file.
#
# @category Foo
#

def is_ghidra():
    return "currentProgram" in globals()

def get_file():
    if is_ghidra():
        selected_file = askFile("FILE", "Choose file:")
        return str(selected_file)
    else:
        return "../test2.def"

def load_def(path):
    """
LIBRARY	BASENAME_OF_LIBRARY
EXPORTS
	name	@10000
"""
    output = {}
    current_category = None
    with open(path) as f:
        z = f.readlines()
    for l in z:
        indented = l.startswith("\t") or l.startswith(" ")
        t = l.split()
        if not t:# empty line.
            continue
        if t[0].startswith(";"):
            continue # comment
        if not indented:
            if len(t) == 1:
                current_category = t[0]
            elif len(t) == 2:
                output[t[0]] = t[1]
            continue; # category
        #print(t)
        if len(t) >= 2:
            name = t[0]
            ordinal = t[1]
            if not ordinal.startswith("@"):
                print("Unhandled ordinal token: {}".format(ordinal))
                continue
            if not current_category in output:
                output[current_category] = {}
            output[current_category][int(ordinal[1:])] = name
        else:
            print("Unhandled: {}".format(t))
    return output
    


if not is_ghidra():
    # We can run in isolation as a test
    def_path = get_file()
    defs = load_def(def_path)
    print(defs.keys())
    print(defs)
    import sys
    sys.exit(1)


def rename_function(func, lookup):
    function_name = func.getName()
    prefix = "Ordinal_"
    if prefix in function_name:
        try:
            ordinal_id = int(function_name[len(prefix):])
        except ValueError as e:
            print("Skipping {} because {}".format(function_name, str(e)))
            return
        print("Found {}".format(ordinal_id))
        new_name = lookup.get(ordinal_id, None)
        if new_name:
            print("Remap {} to {}".format(function_name, new_name))
            func.setName(new_name, ghidra.program.model.symbol.SourceType.DEFAULT)


# https://class.malware.re/2021/03/08/ghidra-scripting.html
# https://github.com/HackOvert/GhidraSnippets

def_path = get_file()
defs = load_def(def_path)
print(defs.keys())


import sys

currentProgram = state.getCurrentProgram()
name = currentProgram.getName()
print(name)

lib_dll = defs["LIBRARY"] + ".DLL"
print(defs)

if lib_dll in name.upper():
    print("We loaded the def for THIS library, using the exports of the defs to rename functions.")
    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True) # True means 'forward'
    for func in funcs: 
        print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))
        rename_function(func, defs["EXPORTS"])
else:
    print("We loaded a defs for another library, using the imports.")
    sm = currentProgram.getSymbolTable()
    symb = sm.getSymbolIterator(True)
    fm = currentProgram.getFunctionManager()
    for s in symb:
        if s.getSymbolType() == ghidra.program.model.symbol.SymbolType.FUNCTION:
            #if not s.isExternal():
            #    continue
            if s.getParentSymbol().getName() == lib_dll:
                addr = s.getAddress()
                f = fm.getFunctionAt(addr)
                print("{} matches lib, addr {}, f: {}".format(s, addr, f))
                rename_function(f, defs["EXPORTS"])

