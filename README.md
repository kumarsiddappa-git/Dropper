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

void * exec_mem;

LPVOID VirtualAlloc(  
  LPVOID lpAddress,                // Starting address from which the allacotion should happen , exmple a memory  
  SIZE_T dwSize,                  // Size of the memory to be allocated   
  DWORD  flAllocationType,        // What kind of allocation for the memory to be allocated like MEM_COMMIT, MEM_RESERVE 
  DWORD  flProtect                // Memory Protection to be allocated PAGE_EXECUTE , PAGE_READWRITE etc   
);  


Sample line of code => exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);  here we are allocting the memory from 0 address until payload_len, we are having a allocation type as MEM_COMMIT and MEM_RESERVE and giving the permission as PAGE_READWRITE just to avoid the EDR triggering as suspicious if the allocated memory is given directly as PAGE_EXECUTE  

We can find more detailed information in the link [VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)

Next API Used is RtlMoveMemory, which is used to copy the payload from Source to Destination

VOID RtlMoveMemory(  
  VOID UNALIGNED *Destination,   // Where to move the memory     
  const VOID UNALIGNED *Source,   // From where to move the payload  
  SIZE_T         Length           //size of the payload  
);  


Sample line of code => RtlMoveMemory(exec_mem, payload, payload_len); , here the payload is moved to address pointed or allocated from the VirtualAlloc API  

We can find more detailed information in the link [RtlMoveMemory](https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory)

Next API is VirtualProtect, which Changes the protection on a region of committed pages in the virtual address space of the calling process.

BOOL VirtualProtect(
  [in]  LPVOID lpAddress,    // Source address or address to which we need to change the protection or permission   
  [in]  SIZE_T dwSize,       // Size of the memory to change the protect   
  [in]  DWORD  flNewProtect, // New Protection we apply from the old protection   
  [out] PDWORD lpflOldProtect // A pointer to a variable that receives the previous access protection value, that is initial page  
);  

Sample line of code => rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);  the exec_mem which has the payload or pointing to the payload had a protection PAGE_READWRITE initially and now its being changed to PAGE_EXECUTE_READ

We can find more detailed information in the link [VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)

Next API would be CreateThread, which creates thread in the process 

HANDLE CreateThread(  
  [in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,     // A pointer to a SECURITY_ATTRIBUTES structure that determines whether the returned handle can be inherited by child processes.  
  [in]            SIZE_T                  dwStackSize,    // The initial size of the stack, in bytes  
  [in]            LPTHREAD_START_ROUTINE  lpStartAddress, //   This pointer represents the starting address of the thread  
  [in, optional]  __drv_aliasesMem LPVOID lpParameter,    //  A pointer to a variable to be passed to the thread.  
  [in]            DWORD                   dwCreationFlags,  // The flags that control the creation of the thread  
  [out, optional] LPDWORD                 lpThreadId   //  A pointer to a variable that receives the thread identifier  
);   

Sample line of code => th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0); LPTHREAD_START_ROUTINE  Points to a function that notifies the host that a thread has started to execute and exec_mem start of payload to start

We can find more detailed information in the link [CreateThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread)


Now lets start to understand how it can be visualized 

The code is attached which you can compile using gcc and create a obj and exe file 

Execute the code and open the x64dbg and attach the exe file 

![image](https://github.com/user-attachments/assets/cf89bd7e-67a1-4157-acd0-3bd2aa0f95b8)

Click on the Attach 

![image](https://github.com/user-attachments/assets/5ff7f1db-0865-4a9c-8366-f88c855cf9ee)

Once clicked select the code or exe which we executed 

![image](https://github.com/user-attachments/assets/18d1601d-92b0-43b5-9656-9ac74500839a)


Now we can see the x64dbg is in Paused state so we need to run the debugger by clicking on . once run it moves to Running 

![image](https://github.com/user-attachments/assets/b4d20ec6-883f-4879-afa6-b66156fe7078)


Now lets go to the code and press Enter so once we press Enter we go to INT3 code in our code or payload as per the screnshot 

![image](https://github.com/user-attachments/assets/f13ccd89-d671-48ec-837f-3572d9319833)  

In the above image we can see the payload we had in our code is being show , for example i am pasting the payload we have in the code 

unsigned char payload[] = {  
		0x40,		// INC EAX  
		0x90,		// NOP  
		0xcc,		// INT3  
		0xc3		// RET  
	};  

 








