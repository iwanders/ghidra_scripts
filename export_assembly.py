# Print assembly for the current function.
#
# @category iwanders
#
from binascii import hexlify

# combined from
# https://github.com/HackOvert/GhidraSnippets/blob/master/README.md#print-all-instructions-in-a-select-function
# https://github.com/HackOvert/GhidraSnippets/blob/master/README.md#get-a-function-name-by-address
functionManager = currentProgram.getFunctionManager()
addr = currentLocation.address
func = functionManager.getFunctionContaining(addr)

listing = currentProgram.getListing()
addrSet = func.getBody()
codeUnits = listing.getCodeUnits(addrSet, True) # true means 'forward'

for codeUnit in codeUnits:
    print("0x{} : {:16} {}".format(codeUnit.getAddress(), hexlify(codeUnit.getBytes()), codeUnit.toString()))
