import angr

proj = angr.Project('./chal', main_opts={'base_addr': 0x0})

simgr = proj.factory.simulation_manager()

simgr.explore(find=0x1445)

if simgr.found:
    print(simgr.found[0].posix.dumps(0))
else:
    print("Not found")
