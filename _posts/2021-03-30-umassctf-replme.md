---
title: 'UMassCTF''21 replme writeup'
date: 2021-03-30 00:00:00+0800
excerpt: Writeup for the challenge replme (and replme2) in UMassCTF'21
comments: true
---

* TOC
{:toc}

## Introduction
For the past weekend, out of boredom, I had decided to take a look at one of the ongoing CTFs, UMassCTF'21. I was pleasantly surprised by how interesting the pwn challenge replme was. It was a lot of fun doing it and unfortunately because of a lot of serious overthinking. I ended up spending two days on what could have been a challenge solvable in an hour. 

## Analysis
Running the given 64-bit binary, we see a prompt of something called Janet with a version and build number as well as copyright text. Instinctively, we can tell this was likely not some custom written code by the author but rather likely some open source project. With Google, we quickly discover we are pwning the lisp style language [Janet Lang](https://janet-lang.org). Previously in another CTF, I had attempted a quickjs pwn challenge where we were given an old version of quickjs and basically free to use any n-day (or 0-day if you so wish) bug to get RCE. As such, I plugged the commit from the janet binary into git and started to take a look at the commits that followed. Interestingly, the commit that followed at [894877a0e378595ba7686e40d52e046649d52389](https://github.com/janet-lang/janet/commit/894877a0e378595ba7686e40d52e046649d52389) appeared to be a security patch.

![](/images/6/poc.png)
*Interesting PoC*

I zoomed in on the PoC for "issue #142 nanbox hijack 3" and decided to give it a go. By unmarshaling an interesting buffer of bytes, we get a strange cfunction of address  0x123456789abc. Calling it, we get a segfault which showed that the RIP of the janet binary was directly changed to that address. So we seem to have gotten RIP control, but why? To understand this, we have to understand what the commit's comment meant by NaN-boxing.

![](/images/6/debugsegfault.png)
*RIP control*

Similar to Google's v8, janet lang represents floating point numbers as 8 byte values (or a QWORD) in memory using the [IEEE754 double-precision binary floating point format](https://en.wikipedia.org/wiki/Double-precision_floating-point_format). In this format, however, not all of the 256^8 variations of the QWORD represent a valid floating point number. Simply put, any little-endian QWORD that exceeds or is equal to 0x7FF0000000000000 is considered a NaN, and NaNs are all identical regardless of the actual in memory representation. NaN-boxing cleverly makes use of this fact by wrapping other data types such as pointers by adding something like 0xfffd800000000000 to the pointer value and storing them as you would for floating point numbers. When janet reads a QWORD, there is no ambiguity on whether it is a valid floating point number or a pointer: if it is not a NaN, it is a floating point number; otherwise, subtract the wrapping value off the "NaN" to obtain the actual pointer value. To make things better, different wrapping values such as 0xfffd800000000000 and 0xfffb800000000000 are used to denote different data types such as arrays, functions and others. This has no ambiguity as well because 64-bit pointers use only 48 bits or 6 bytes of the 8 byte address space, leaving the top 2 bytes usually as 0s (vdso and gang aside). The second LSB of the wrapping value will therefore be preserved after addition and can be used to identify the pointer type.

Looking back at the commit's PoC, we are unmarshalling the value 0xfffe923456789abc or (0xfffe800000000000 + 0x123456789abc). The first byte of the buffer, 0xc8, is the enum value LB_REAL in [marsh.c](https://github.com/janet-lang/janet/blob/master/src/core/marsh.c) and denotes that the following 8 bytes is a real number. I did not debug further, but somewhere along the line the code must have forgotten to treat the real number as *only* a real number and did NaN-boxing unwrapping on it, resulting in it being interpreted as a cfunction. Bummer!

![](/images/6/sad.png)
*Oh no*

After a day of writing a semi-working deref leaking exploit, I realised that marshal was disabled on the target. Needless to say, that was pretty devastating. Some readers \(especially those who solved the challenge\) may be wondering, isn't there another PoC above the unmarshaling from line 116-126 in the patch test/suit7.janet? For some incredible reason, only now in writing this post did I realise that I had **complete ignored** these lines while looking at the commit. In fact, I only stumbled upon that same PoC again because I was searching for the word 'vulnerability' in the repo's issues. Facepalm. Anyways, pasting the typed array PoC into the challenge's web prompt shows that it works.

![](/images/6/firstsuccess.png)
*Hey this works*

Skipping all the failed attempts and ideas in between, my final solution is as follows. It was obvious that functions such as os/execute and marshal were disabled in the challenge, but what was interesting was their types. These functions are implemented in the janet binary itself as C code and thus are cfunctions, yet in the challenge they became non-native functions. This led me to theorise that our input is prepended with a script that uses variable assignment to overwrite the restricted functions. This meant that if we could find the addresses of the actual cfunctions in memory, we could likely still call them.

![](/images/6/compare.png)
*Running janet binary locally \(left\) and remote \(right\). Notice on remote cfunctions have became functions*

I chose a random cfunction that is not forbidden such as peg/compile and assigned it to the first element of an 8-element array. I then induced an error by trying to call the array and from extracted its address from the error message. Not that efficient, but oh well. Recall that different wrapping values denote different types in janet lang. By adding the *buffer* wrapping value to the array's pointer and using the fakeobj primitive from the commit, I type confused the array into a buffer. Arrays and buffers have almost the same struct in memory, except they operate on QWORDs and bytes respectively. With the buffer, we can still access 8 elements, but now each element is only a single byte in length, which meant we are now accessing individual bytes of the first QWORD in the original array. This thus allows us to read out the address of peg/compile.

![](/images/6/diagram.png)
*Type confusion of array and buffer*

After obtaining the offsets for peg/compile and os/execute respectively, all we have to do is to calculate the address of the cfunction os/execute. We then add the wrapping value for a cfunction to it and use the fakeobj primitive once again. Calling our os/execute variable as the documentation indicates, we see that we have managed to get RCE. Interestingly, this was only the intended solution for replme2 as replme apparently had a blacklist bypass, according to replme2's description. Nonetheless, I managed to pwn both challenges just by reusing the same exploit :\).

![](/images/6/symbols.png)
*Symbols of os/execute and peg/compile are 0x1f2a0 and 0x24900 respectively*

![](/images/6/win.png)
*2x win*

## Conclusion
As usual, I always prefer pwn challenges that are related to real life pwn scenarios, and this was an absolute treat to me. What is not documented in this blog post was the hours spent over the course of the 2 days trying to obtain LIBC addresses, obtain arbitrary r/w as well as just straightup dumping the libc binary from memory. In the end, when I saw the obvious path, the whole challenge became rather straightforward and the final exploit took half an hour to develop. The final exploit can be found [here](https://gist.github.com/YiChenChai/17f3441ba158a6c5c5b34ad2b2a0e01d).
