from pwn import *
from rich import print

context.binary = elf = ELF('./rev')
context.log_level = 'warn'

solution = bytearray([0 for _ in range(12)])

# solution = bytearray(b"aN0lheF1HGR=%nF!or<iS_tHis_iT")

def dfs(pos):
    if pos >= 12:
        return
    for i in range(0x20, 0x7f):
        log.info(f'Trying {i} for pos {pos}')
        solution[pos] = i
        p = elf.process()
        # I manually guessed the remaining chars here
        # from seeing patterns in the solver output
        p.sendline(solution + b'ing_or_iS_tHis_iT')
        try:
            result = p.recvline()
        except EOFError:
            log.warn('EOFError')
            p.close()
            continue
        p.close()
        # log.warn(result)
        if b'Correct' in result:
            print(solution)
            exit()
        idx = int(result.split(b': ')[0], 16)
        if idx > pos:
            # we found a byte that is correct
            # print(f'Found byte {pos}: {solution[pos]}')
            log.warn(f'Correct byte is {i} for pos {pos}')
            log.warn(f'solution so far: {solution}')
            dfs(idx)
            log.warn(f'Backtracking from pos {pos}')
            # possible_bytes.append(i)
            # pos = idx
            # break
        solution[pos] = 0

dfs(0)
# aN0ther_HeRRing_or_iS_tHis_iT
