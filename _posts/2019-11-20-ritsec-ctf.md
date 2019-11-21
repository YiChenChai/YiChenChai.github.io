---
title: '2019 RITSEC CTF wumb0list writeup'
date: 2019-11-20 00:00:00
excerpt: Writeup for the challenge wumb0list for RITSEC CTF
comments: true
---
## Introduction
On last weekend I had a chance to take a look at a few pwn challenges from RITSEC CTF. Due to the little time I had from other work and limited ability, I only managed to solve wumb0list. Apparently, this approach of solving is unintended. Anyways, here's the (belated) writeup! Skip to the conclusion to find the exploit.

## Challenge analysis
The challenge is the typical linux pwn challenge, a 64-bit stripped non-C++ ELF binary.

![](/images/2/binary.png)
*Typical binary*

As part of the regular routine, I plugged the binary into IDA. We see a menu system with 2 submenus to managed an "item catalog" and a "shopping list". From experience, together with malloc and free in the GOT functions, it is likely that this is a heap challenge.

![](/images/2/main.png)
*Main menu*

![](/images/2/catalog.png)
*Catalogue menu*

![](/images/2/list.png)
*List menu (sorry not sure how to play images side by side)*

After wasting an hour on IDA decompilation mistakes in the catalog code that looked like the use of uninitialised variables, I proceeded to check the list code. Bingo! The code had an obvious off-by-one bug.

![](/images/2/thevuln.png)
*The vulnerability*

Each list was stored as 2 quadword (16 bytes in total) pointers, the first pointing to its name and the second pointing to a singly linked list of items. While the array storing the list pointers was 160 bytes, or allowed **10 lists** at most, the list deletion as well as viewing code allowed us to go up to **index 10**, which meant accessing 16 bytes_outside of the storage array on the stack.

![](/images/2/whatfollows.png)
*What follows*

![](/images/2/nameusage.png)
*How name is used*

What comes after the storage array on stack? As it turns out, it's a 0x400 byte buffer that stores any name we enter for catalog items or lists temporarily. We shall call it 'name' for easy reference later.

The approach was apparent at this point. Through populating the name buffer with any pointer of our choice, we can derefence and leak the data pointed by the pointers with the view list function, or free them with the delete list function.

![](/images/2/heapdiag.png)
*Poorly drawn diagram of the heap*

My idea was to free a fake heap chunk that overlapped in the middle of two real ones, so that when all 3 chunks are freed, the real ones can be allocated again to overwrite the next pointer in the fake chunk on the tcache, getting arbitrary write.

![](/images/2/leakcode.png)
*The codepath we use for leaking*

So to begin off, we start the exploit with a regular leak of LIBC base address. As previously mentioned, the first 16 bytes of the name buffer are incorrectly treated as a list name pointer and head pointer to a singly linked list. Luckily for us, PIE is not enabled so the address space for the binary itself is not randomised. For the list name pointer, I simply entered a GOT address. For the head pointer, it had to be non-null for the name to be printed as shown.

```
proc.sendlineafter('FAM', '2')
proc.sendlineafter('Back', '1')
proc.sendlineafter('Choose wisely: ', p64(0x603020) + p64(0x6030d8))
```

![](/images/2/theleak.png)
*Leak success!*

![](/images/2/analysisbss.png)
*What the BSS contains*

This part was a bit tricky because of the derefencing and %s used in the printf statement which limited where we can point the head to. Ultimately I found a location on the BSS which preceded the stdout FILE pointer which did the trick. As an additional bonus, because the challenge author omitted setvbuf calls to disable buffering on stdout, the stdout FILE struct used the heap for buffering output, leaking us a heap address as well.

![](/images/2/howtoalloc.png)
*The code that adds catalog items*

To make the real heap chunks, I decided to use the catalog code. The code took input for a name, copied it into a heap chunk, and allocated another heap chunk to store catalog info. While I initially thought of directly entering name via stdin, it was not a good choice because the heap copying involved calling strdup on my input, which meant the data will be terminated on first null byte.

However, the code had an option to import catalogs, which used memcpy'd our user supplied name to a heap chunk based on our provided size. I imported 2 catalog items of names of sizes 0x50 each. The first name had a fake header for a heap chunk of size 0x50, 0x20 bytes into the name. The second name began with a second fake header to correspond with the previous header (prevsize and previnuse checks in free). 

![](/images/2/heaplayout.png)
*Notice the last 3 entries before the top chunk*

![](/images/2/aftermath.png)
*The aftermath of our exploit (sizes displayed are real chunk size + 16 as the chunk header is 16 bytes)*

Then, with the heap leak gotten, the fake chunk's location is calculated and placed onto the first 8 bytes of the name buffer and the next 8 bytes are set to 0. With the list deletion function, we free the fake chunk. We then legitimately free the 1st real chunk.

![](/images/2/rightbefore.png)
*Free hook is on the heap now*

With the catalog import function, we import a single catalog item with name of length 0x50 again. Malloc returns available previously free'd chunks first, so our the name is copied into our previous 1st real chunk, overwriting the fake chunk first few quadwords. Armed with a LIBC leak, we overwrite the next pointer of the fake chunk to \_\_free_hook. Initially testing locally, I didn't bother looking at the remote LIBC and did a fastbin dup technique. Discovering the target used LIBC 2.27 with tcache in fact made the exploit _slightly_ easier as there is less constraints on the next pointer of the fake chunk.

![](/images/2/freehook.png)
*Free hook overwritten*

We now just import a third file with 2 names of size 0x60. The chunk used for the first name will be the fake chunk, but the second chunk will begin at _\_\_free_hook_. I initially overwrote free hook with system and tried to free a string in the LIBC pointing to /bin/sh to get system('/bin/sh'). For some strange reason, despite wumb0list running as root, the sh shell dropped to the regular user. Next, I tried overwriting free with a one_gadget. Due to ingenious idea (of team 217) of jumping to code inside the system function right before it made an execve syscall, the code should also drop a shell, just that execve replaces the original process with sh. That didn't work either.

![](/images/2/rop.png)
*Increase rsp until we are inside name buffer*

After a break, I decided to try doing a ROP. While with arbitrary write providing quite a few options for ROP, I had a relatively simple idea. As the name buffer was already on the stack, I simply overwrote free hook with a gadget that shifted rsp into the name buffer. Given that it was 0x400 bytes, there was a lot of leeway for a gadget that didn't shift rsp precisely to the buffer start.

![](/images/2/jackpot.png)
*Flag got*

The rest was trivial. With a small mprotect ropchain to make memory rwx from ropper and premade cat file shellcode from pwntools, I managed to get the flag.

## Conclusion
The exploit can be found [here](https://gist.github.com/YiChenChai/368c01980ad2d451f92cefbc3f820971). This pwn challenge was pretty straightforward given the easily accessible malloc, free and leak primitives (unintended by organisers?). It was a good choice in retrospect to begin with a challenge with little solves; sometimes challenges are not as hard as their solve count may imply.
