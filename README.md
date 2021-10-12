# HandleKatz_BOF


## What is this?
This is a (mostly complete) port of the functionality presented by [@thefLink](https://twitter.com/thefLinkk) and [Code White GmbH](https://twitter.com/codewhitesec).  You guys deserve a large amount of thanks for taking the time to present your research!


## Why?
This was a personal question to answer if this would work within `Cobalt Strike`, and if so, how?


## What are the options this currently supports
- There are two required parameters, a `PID` and a filepath to write the dumpfile to. (e.g. `handlekatz 780 C:\Users\User\Desktop\obfuscated.dmp`)


## How do I run this?
1. In this case, you have two options:
	1. Use the existing, compiled object file, located in the `dist` directory (AKA proceed to major step two)
    2. Compile from source via the `Makefile`
        1. `cd src`
        2. `make clean`
        3. `make`
2. Load the `Aggressor` file, in the `Script Manager`, located in the `dist` directory


## Any known downsides?
- We're still using the `Win32` API and `Dynamic Function Resolution`.  This is for you to determine as far as "risk"
- You may attempt to incur a privileged action without sufficient requisite permissions.  I can't keep you from burning your hand.

## Where can we go from here?
- Implement the one remaining overt `Win32 API` call invoked with the `Dynamic Function Resolution` syntax (`VirtualAlloc`) to be a call to `NtAllocateVirtualMemory`.  I've included the necessary header(s) with implementation in `syscalls.h`.  Enjoy! :)
