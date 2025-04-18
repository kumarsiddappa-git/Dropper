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

1. VirutallAlloc is an API which is defined in Kernel32.dll, which allocates a memory in the process we mention

LPVOID VirtualAlloc(  
  LPVOID lpAddress,                // Starting address from which the allacotion should happen , exmple a memory  
  SIZE_T dwSize,                  // Size of the memory to be allocated   
  DWORD  flAllocationType,        // What kind of allocation for the memory to be allocated like MEM_COMMIT, MEM_RESERVE 
  DWORD  flProtect                // Memory Protection to be allocated PAGE_EXECUTE , PAGE_READWRITE etc   
);  


Sample - exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);  here we are allocting the memory from 0 address until payload_len, we are having a allocation type as MEM_COMMIT and MEM_RESERVE and giving the permission as PAGE_READWRITE just to avoid the EDR triggering as suspicious if the allocated memory is given directly as PAGE_EXECUTE
We can find more detailed information in the [link](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
