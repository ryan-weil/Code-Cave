# Code-Cave
It is simple to inject shellcode (position-independent code). However, I have not seen an example where someone injects **position-dependent** code which requires relocations. This project injects a MessageBox into a code cave in an executable file, and applies relocations to the injected code.

# Notes
**The file must already have the API (MessageBoxA) in its Import Address Table.** Injecting the import into the IAT of the file is possible but incredibly complicated to do, because it would require a large amount of adjustments to the other sections and offsets/addresses. At that point, it would be much more logical to write position-independent code.

# Screenshots

Demo injection into putty:

![](https://i.imgur.com/5gJpsNz.gif)
