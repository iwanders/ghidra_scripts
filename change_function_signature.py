# Change function signatures.
#
# @category iwanders
#


# helpful links:
#https://github.com/NationalSecurityAgency/ghidra/issues/1126
#https://github.com/NationalSecurityAgency/ghidra/issues/3599

def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

from ghidra.program.flatapi import FlatProgramAPI
state = getState()
program = state.getCurrentProgram()
fpapi = FlatProgramAPI(program)

# actual thing to change a function signature
# https://ghidra.re/ghidra_docs/api/ghidra/app/cmd/function/ApplyFunctionSignatureCmd.html
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd

# function signature itself:
# https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/FunctionDefinitionDataType.html
from ghidra.program.model.data import FunctionDefinitionDataType
# https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/GenericCallingConvention.html
from ghidra.program.model.data import GenericCallingConvention
# function arguments:
from ghidra.program.model.data import ParameterDefinitionImpl
# To make a pointer argument.
from ghidra.program.model.data import PointerDataType

# https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/SourceType.html
from ghidra.program.model.symbol import SourceType

# print(Pointer.docs)

# try to construct it.
new_fun = FunctionDefinitionDataType("hello")
possible_datatypes = fpapi.getDataTypes("dword")
print(possible_datatypes);
arg1_datatype = PointerDataType(possible_datatypes[0]);
arg1_ordinal = 0;
arg1 = ParameterDefinitionImpl("thing", arg1_datatype, "comment")
new_fun.setArguments([arg1])


convention = GenericCallingConvention.fastcall
new_fun.setGenericCallingConvention(convention)

print(new_fun)

source = SourceType.ANALYSIS

fun_addr = getAddress(0xDEADBEEF)

# finally, build the command
cmd = ApplyFunctionSignatureCmd(fun_addr, new_fun, source)

# And invoke it!
cmd.applyTo(currentProgram)
