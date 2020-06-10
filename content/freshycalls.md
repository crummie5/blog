+++
title = "FreshyCalls: Syscalls Freshly Squeezed!"
date = 2020-06-10

[taxonomies]
tags = ["Windows"]

[extra]
authors = "ElephantSe4l"
preview_summary = "FreshyCalls is a library that tries to make the use of syscalls comfortable and simple, without generating too much boilerplate and in modern C++!"
preview_image = "fig1.png"
+++

These last months I've been familiarizing myself with Windows syscalls: how they work, their offensive usage and potential detections from the blue side. Although the theory was quite interesting, I had to get my hands on it. 

I started with the basics: static syscalls for my version of Windows. 

As I'm not a pentester - I'm a programmer - I found it too uncomfortable to have to define each syscall each time. That's why I made a list with all the syscall numbers and a template that mapped each syscall with each number in a global variable. 

<!-- more -->

It was something like this:

syscall.asm:
```asm
EXTERN syscall_no:DWORD

.code

call_syscall PROC
    mov r10, rcx
    mov eax, syscall_no
    syscall
    ret
call_syscall ENDP

END
```

syscall.cpp:
```cpp
extern "C" DWORD syscall_no = 0;
extern "C" void* call_syscall(...);

[...]

DWORD syscall_no = syscalls.find("NtReadVirtualMemory");
call_syscall(h_process, mem_addr, &buf, mem_size, nullptr);
```

For a while it worked like a charm. But as soon as we started making some tools, Windows versions knocked on the door. Honestly, having to depend on every version of Windows to extract syscall numbers was something unnacceptable... so we looked up for solutions.
Fortunatelly - and thanks to evilsocket - we found the following [post](https://www.evilsocket.net/2014/02/11/on-windows-syscall-mechanism-and-syscall-numbers-extraction-methods/). In this way we could extract all the syscall numbers directly in runtime. It was a big improvement! Indeed, it was what we had implemented until recently.

Once I had these problems solved, I wanted to study more about how to detect the use of syscalls (they can't be the holy grail!)

## First Detection: The Number Extraction

We started reading [this Cyberbit post](https://www.cyberbit.com/blog/endpoint-security/malware-mitigation-when-direct-system-calls-are-used/). The post explained three different methods of numbers extraction with their pros and cons - along with their detection. 

{{ figure(name="fig1.png", caption="Comparative table taken from Cyberbit's blog.") }}

In our implementation we used the first method which apparently - and according to Cyberbit - was not that bad (nice!). But we still wanted to improve it. 
We looked at the third method: reading the ntdll.dll module already loaded in the process. It seemed the best approach, but there was a warning: "Fails if the functions are hooked by a security product"

Example:

{{ figure(name="fig2.png", caption="Cylance's hook in ntdll.dll.") }}

If we checked NtReadVirtualMemory with Cylance installed, we would notice that our syscall number is nowhere (fuck). On the other hand, the last of the methods was supposed to be worser than the one we used, so we gave it up and continued investigating.

Few weeks later we noticed a really interesting relationship between the address of the stub and its corresponding syscall number. The stub with the lowest memory in Windows 10 1909 is NtAccessCheck and if we check the associated syscall number... it is 0! the lowest syscall number! If we check the second with the lowest memory - NtWorkerFactoryWorkerReady - it is 1! The second lowest syscall number! 

What's going on here? We are not really sure, but we think the reason might be that as the syscall number is used to calculate the offset towards the real system service, it somehow needs this relationship to work.

1. We don't read ntdll from disk
2. We don't map a second ntdll to the process
3. We don't read the already loaded ntdll

So... do we have superpowers now? 

Not really. Defenders **MAY** not be able to detect us at runtime, but a little of reverse engineering would spot malicious activities. Furthermore, they may not detect the extraction, but what about the execution?


## Second Detection: Manual Syscall Execution

We already have the extraction, yet what about the execution? can this be detected? 

At first we didn't think sycall executions could be registered/detected, but in fact ETW can do the job. However, we didn't find a way to detect if an execution was done MANUALLY or if it was a regular legitimate one.

While researching about this topic I ended up on the ScyllaHide repo and saw that they had a function that seemed to detect manual syscalls [here](https://github.com/x64dbg/ScyllaHide/blob/master/HookLibrary/HookedFunctions.cpp#L176-L187). They were using something I didn't know at that time called InstrumentationCallback. 
After a simple search I found a [repo](https://github.com/ionescu007/HookingNirvana) and a [video](https://www.youtube.com/watch?v=bqU0y4FzvT0) of a talk that Ionescu gave. With this thing - InstrumentationCallback - we can have a callback every time the CPU returns from kernel-mode to user-mode (i.e. when the system service called has already finished). This allowed us to know what the service output was and the return address. 

ScyllaHide's manual syscall detection is based of checking if the return address is within the memory range corresponding to the EXE. If it is, it's spotted as a manual syscall.

What can we do about that? Let's check out what the stub of a syscall looks like. On Windows 10 you will see something like this:

```asm
mov    r10, rcx
mov    eax, 0x3f
test   BYTE PTR ds:0x7ffe0308, 0x1
jne    0x15
syscall
ret

int    0x2e
ret
```

What if we run our syscall in the original stub? We could jump to the syscall instruction and have it follow the execution instead of returning directly to our EXE (i.e. do the ret instruction). Following this approach we could bypass that check but be aware that didn't mean it was good. 

Yes, we bypass that check. But we also leak which syscall has been executed. So it's up to you and your operational situation.


## And finally... Our library

{{ figure(name="fig3.png", caption="PoC of our library.") }}

Everything we've exaplained might be cool for someone, but doing it manually every time... it's not that cool. And that's why we have released this library! 

We tried to make the use of syscalls comfortable and simple without generating too much boilerplate. For this purpose, we have implemented a series of functions for error handling, reading memory, calling module functions... 
Let's look at some examples of the error handling for instance:

```cpp
freshycalls.caller<NTSTATUS>("NtOpenProcessToken", HANDLE(-1), TOKEN_ADJUST_PRIVILEGES, &h_token).
      throw_if_unexpected(NTSTATUS(0),
                          "[active_sedebug] Something happened opening the current process token:: 0x{{result_as_hex}}");
```

```cpp
auto const dos_header = read_mem<IMAGE_DOS_HEADER>(h_process, module_addr, sizeof(IMAGE_DOS_HEADER)).
      throw_if_unexpected(NTSTATUS(0),
                          "[get_function_addr] Something happened reading the IMAGE_DOS_HEADER of the module at %p inside a remote process: 0x{{result_as_hex}}",
                          module_addr);
```

`throw_if_unexpected` takes an expected result, an error message (or a template) and the arguments needed to format the message. For more examples you have our [PoC](https://github.com/Crummie5/Freshycalls_PoC/) and the [lib code](https://github.com/Crummie5/Freshycalls) itself.

Be aware we have released this library "for fun" and it is by no means perfect. You should expect some bugs and undefined behaviours. Nonetheless if good feedback is received, we might consider continuing the development (also contributions would be really apreciated).

Take care!

~ ElephantSe4l 


## Aknowledgements 

Thanks to:
- [@franky_tech](https://twitter.com/franky_tech),  [@sniferl4bs](https://twitter.com/sniferl4bs), [@pieldepanceta](https://twitter.com/pieldepanceta) and [@khsan](https://twitter.com/khsan) for letting us take samples of some EDRs and AVs.
- All the Crummie5 for reviewing this post and covering my fool tracks.
