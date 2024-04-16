import angr

proj = angr.Project('./sunshine')

payload = b''
with open('payload', 'rb') as f:
    payload = f.read()

addrs = [0x4010c0, 0x401670, 0x000000000040163a]

trace = angr.exploration_techniques.Tracer(trace=addrs, copy_states=True, aslr=False)

state = proj.factory.entry_state(
    mode = 'tracing',
    stdin=payload
)

simgr = proj.factory.simgr(state)

simgr.use_technique(trace)
simgr.run()

