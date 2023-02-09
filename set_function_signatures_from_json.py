# Set function signatures from a json file.
#
# @category iwanders
#

# helpful links:
#https://github.com/NationalSecurityAgency/ghidra/issues/1126
#https://github.com/NationalSecurityAgency/ghidra/issues/3599



# actual thing to change a function signature
# https://ghidra.re/ghidra_docs/api/ghidra/app/cmd/function/ApplyFunctionSignatureCmd.html
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd

# function signature itself:
# https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/FunctionDefinitionDataType.html
from ghidra.program.model.data import FunctionDefinitionDataType
# https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/GenericCallingConvention.html
from ghidra.program.model.data import GenericCallingConvention
# function arguments: https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/ParameterDefinitionImpl.html
from ghidra.program.model.data import ParameterDefinitionImpl
# To make a pointer argument: https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/PointerDataType.html
from ghidra.program.model.data import PointerDataType

# https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/SourceType.html
from ghidra.program.model.symbol import SourceType


import json
"""
{
  "header_file.h": [
    {
      "library": "OurLibrary",
      "address": 1876641120,
      "valid": true, // only use if.
      "return": {
        "pointers": 0,
        "type": "void"
      },
      "function_name": "MyFun",
      "args": [
        {
          "type": {
            "pointers": 1, // so a pointer to this, 2 would be a pointer to a pointer.
            "type": "MyStruct"
          },
          "name": "pUnit"
        },
        {
          "type": {
            "pointers": 0,
            "type": "int"
          },
          "name": "my_integer_by_value"
        }
      ]
      "calling_convention": "stdcall"
    },
"""

def create_data_type(data_spec, fpapi):
    possible_datatypes = fpapi.getDataTypes(data_spec["type"])
    if len(possible_datatypes) == 0:
        return None
    elif len(possible_datatypes) > 1:
        print("  Got multiple possible data types: {}, using first.".format(list(possible_datatypes)))
    t = possible_datatypes[0]
    for k in range(data_spec["pointers"]):
        t = PointerDataType(t)
    return t

def create_calling_convention(s):
    l = {
        "cdecl": GenericCallingConvention.cdecl,
        "fastcall": GenericCallingConvention.fastcall,
        "stdcall": GenericCallingConvention.stdcall,
        "thiscall": GenericCallingConvention.thiscall,
        "unknown": GenericCallingConvention.unknown,
        "vectorcall": GenericCallingConvention.vectorcall,
    }
    return l.get(s, l["unknown"])

# Convert the above json to the necessary function signature object.
def function_spec_to_signature(function_spec, fpapi):
    # Check if we have a valid function spec.
    if not "valid" in function_spec or not function_spec["valid"]:
        return None

    # Make the functtion with a name
    new_fun = FunctionDefinitionDataType(function_spec.get("function_name", "function_0x{:0>8x}".format(function_spec["address"])))

    # Craft the argument list
    arg_list = []
    for k in function_spec["args"]:
        t = create_data_type(k["type"], fpapi)
        if not t:
            print("  Could not get type for {}".format(str(k)))
            return None
        arg_list.append(ParameterDefinitionImpl(k["name"], t, "comment"))
    new_fun.setArguments(arg_list)

    # Set the calling convention.
    new_fun.setGenericCallingConvention(create_calling_convention(function_spec["calling_convention"]))

    # set the return type.
    t = create_data_type(function_spec["return"], fpapi)
    if not t:
        print("  Could not get return for {}".format(str(function_spec["return"])))
        return None
    new_fun.setReturnType(t)

    # Is there a comment to set?
    comment = ""
    if "comment" in function_spec:
        comment += function_spec["comment"]
    elif "comment_input" in function_spec:
        comment += function_spec["comment_input"]
    new_fun.setComment(comment)

    return new_fun


def attempt_to_assign_function(function_spec, program, fpapi, dry_run=True):
    def getAddress(offset):
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

    # try to construct it.
    # new_fun = FunctionDefinitionDataType("hello")
    # possible_datatypes = fpapi.getDataTypes("dword")
    # print(possible_datatypes);
    # arg1_datatype = PointerDataType(possible_datatypes[0]);
    # arg1_ordinal = 0;
    # arg1 = ParameterDefinitionImpl("thing", arg1_datatype, "comment")
    # new_fun.setArguments([arg1])


    # convention = GenericCallingConvention.fastcall
    # new_fun.setGenericCallingConvention(convention)

    # print(new_fun)
    print("Function at 0x{:0>8x}".format(function_spec["address"]))
    new_fun = function_spec_to_signature(function_spec, fpapi)
    if not new_fun:
        print("  Skipping could not construct function: {}".format(function_spec.get("signature_input", "")))
        return


    source = SourceType.ANALYSIS
    fun_addr = getAddress(function_spec["address"])

    # Create the command
    cmd = ApplyFunctionSignatureCmd(fun_addr, new_fun, source)
    # And invoke it.
    print("  Setting function at 0x{:0>8x} to {}".format(function_spec["address"], new_fun))
    cmd.applyTo(currentProgram)

def set_functions(function_specs, dry_run=True):
    from ghidra.program.flatapi import FlatProgramAPI
    state = getState()
    program = state.getCurrentProgram()
    fpapi = FlatProgramAPI(program)
    for f in function_specs:
        attempt_to_assign_function(f, program, fpapi, dry_run=dry_run)


def load_json(p):
    with open(p) as f:
        return json.load(f)

l = load_json("../signatures.json")

dry_run = False

count_to_do = 0 # set to n to do n functions, set to zero to do all.
if count_to_do:
    functions = []
    for h, f in l.items():
        functions.extend(f)
    set_functions(functions[0:count_to_do], dry_run=dry_run)
else:
    for header_file, functions in l.items():
        print("Header file: {}".format(header_file))
        set_functions(functions, dry_run=dry_run)
        



