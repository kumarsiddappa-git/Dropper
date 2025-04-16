# Dropper
Which sections of the PE we can put our code into


Today Lets try to understand different sections we can place the code or shellcode in the PE file.

PE has many sections , but we would be concentrating on 
1. .text
2. .data
3. .rsrc

To do that lets create a simple code which helps us to understand more , for this we need visual studio (or gcc compiler being installed and use it to compile and create an exe file to run) and x64dbg
https://x64dbg.com/ to download the x64dbg debugger and install is simple 

![image](https://github.com/user-attachments/assets/f97d1670-b7cb-4668-ad9d-2ac625eadeb4)

It's just a sample diagram which shows the different sections we can see in the PE file.

so we shall first discuss on what methods are used to allocate a space in the process memory , move our payload into it and then how to provide the permissions after that we can also see the x64dbg being used to see the payload placement.

1. VirutallAlloc is an API which is defined in Kernel32.dll

    We can find more detailed information in the [link](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
