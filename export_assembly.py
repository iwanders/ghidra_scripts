# Print assembly for the current function.
#
# @category Foo
#

addr = currentLocation.address
#print(currentProgram.getListing().getInstructionAt(addr))
limit = 100
counter = 0
for instr in currentProgram.getListing().getInstructions(addr, True):
    print(instr)
    counter += 1
    if (counter > limit):
        break
