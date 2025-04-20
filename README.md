# Dropper
Which sections of the PE we can put our code into


Today Lets try to understand different sections where the malicious payload or we can place the code or shellcode in the PE file.

PE has many sections , but her we would be concentrating on main three sections. Which are ...  

1. .text
2. .data
3. .rsrc

To do that lets create a simple code which helps us to understand more , for this we need visual studio (or gcc compiler being installed and use it to compile and create an exe file to run) and x64dbg
https://x64dbg.com/ to download the x64dbg debugger and installation is simple 

![image](https://github.com/user-attachments/assets/f97d1670-b7cb-4668-ad9d-2ac625eadeb4)

It's just a simple diagram which shows the different sections we would be seeing in the PE file.

so we shall first discuss on steps 
1. what API methods are used to allocate a space in the process memory  
2. move our payload into the virtually allocated memory  
3. Then how to provide the permissions after that we can also see the x64dbg being used to see the payload placement.
4. Create a Threat inside the current Process. 


VirutallAlloc is an API which is defined in Kernel32.dll, which allocates a memory in the process we mention

		void * exec_memory;
		
		LPVOID VirtualAlloc( 		
		  LPVOID lpAddress,                // Starting address from which the allacotion should happen , exmple a memory  
		  SIZE_T dwSize,                  // Size of the memory to be allocated   
		  DWORD  flAllocationType,        // What kind of allocation for the memory to be allocated like MEM_COMMIT, MEM_RESERVE 
		  DWORD  flProtect                // Memory Protection to be allocated PAGE_EXECUTE , PAGE_READWRITE etc 
		  );  


Sample line of code =>  

	exec_memory = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);  
 
 Here we are allocting the memory from 0 address until payload_len, we are having a allocation type as MEM_COMMIT and MEM_RESERVE and giving the permission as PAGE_READWRITE just to avoid the EDR triggering as suspicious if the allocated memory is given directly as PAGE_EXECUTE  

We can find more detailed information in the link [VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)

Next API Used is RtlMoveMemory, which is used to copy the payload from Source to Destination

		VOID RtlMoveMemory( 		
		  VOID UNALIGNED *Destination,   // Where to move the memory  
		  const VOID UNALIGNED *Source,   // From where to move the payload 
		  SIZE_T         Length           //size of the payload  
		  );  


Sample line of code =>  

	RtlMoveMemory(exec_memory, payload, payload_len); 
 
Here the payload is moved to address pointed or allocated from the VirtualAlloc API  

We can find more detailed information in the link [RtlMoveMemory](https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory)

Next API is VirtualProtect, which Changes the protection on a region of committed pages in the virtual address space of the calling process.

		BOOL VirtualProtect(		
		  [in]  LPVOID lpAddress,    // Source address or address to which we need to change the protection or permission  
		  [in]  SIZE_T dwSize,       // Size of the memory to change the protect
		  [in]  DWORD  flNewProtect, // New Protection we apply from the old protection
		  [out] PDWORD lpflOldProtect // A pointer to a variable that receives the previous access protection value, that is initial page 
		  );  

Sample line of code => 

	rv = VirtualProtect(exec_memory, payload_len, PAGE_EXECUTE_READ, &oldprotect);  
 
 the exec_mem which has the payload or pointing to the payload had a protection PAGE_READWRITE initially and now its being changed to PAGE_EXECUTE_READ

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

Sample line of code => 

	th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_memory, 0, 0, 0); 
 
 LPTHREAD_START_ROUTINE  Points to a function that notifies the host that a thread has started to execute and exec_mem start of payload to start

We can find more detailed information in the link [CreateThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread)


Now lets start to understand how it works using the debugger x64dbg

The code which is attached in the post is which you can compile using gcc and create a obj and exe file , Once the exe file is created follow the steps

1. Execute the code and open the x64dbg and attach the exe file as per the screenshot 

![image](https://github.com/user-attachments/assets/cf89bd7e-67a1-4157-acd0-3bd2aa0f95b8)

Copy the memory address and save it on Notepad or one notes for later use .

2. Click on the Attach, which attaches the running exe file to the debugger

![image](https://github.com/user-attachments/assets/5ff7f1db-0865-4a9c-8366-f88c855cf9ee)

3. Once clicked select the code or exe which is being executed or name of our exe file 

![image](https://github.com/user-attachments/assets/18d1601d-92b0-43b5-9656-9ac74500839a)


4. After the running exe is attached, Now we can see the x64dbg is in Paused state so we need to run the debugger by clicking on run and watch the state moves form Paused to Running. 

![image](https://github.com/user-attachments/assets/b4d20ec6-883f-4879-afa6-b66156fe7078)


5. Now lets go to the terminal where we ran the exe file, which is waiting for our input press Enter key. Once Enter the debugger stops at the INT3 op code which we have in our payload as the screnshot 

![image](https://github.com/user-attachments/assets/f13ccd89-d671-48ec-837f-3572d9319833)  

In the above image we can see the payload we had in our code is being shown , The sample payload being used in the code is being pasted here 

	unsigned char payload[] = {  
			0x40,		// INC EAX  
			0x90,		// NOP  
			0xcc,		// INT3  
			0xc3		// RET  
		};  

 
Now our main objective is to find where the payload is stored and which sections we can see them.

Steps 

1. Got to Memory Map Tab and right click on empty space and select Find Patterns

   ![image](https://github.com/user-attachments/assets/6d702e73-f3a4-4e96-b68e-ce51e8315f3e)

2. Type the payload in the below format and click on Entire block, which is equal to find whole word ...

   ![image](https://github.com/user-attachments/assets/d0357891-3d18-4aa6-9ec9-cdac94509c92)

3. We will get the address where the pattern or payload is saved

    ![image](https://github.com/user-attachments/assets/e3e2c048-72d8-4ad4-9792-05635935dea0)

4. Save the Address we get so we can use them to search accross dissembler

   ![image](https://github.com/user-attachments/assets/028e7178-6936-4c6b-8745-bd1786756e9d)

5. Now lets iterate over each address and find where those payload stays

	   Address           Data
	
																					 
	0000000FF26FF850  40 90 CC C3  
	00000123C4620000  40 90 CC C3  
	00007FF743B0101E  40 90 CC C3  

       1. If we compare the first memory address memory address 0000000FF26FF850 in the Memory Map view, to identify where the payload is placed we can see that is saved on   		stack, now we might get a question why on stack? All the local variables of the functions are saved on stack and here main() is a function and payload is declared as 
        local variable in the code (main function).

![image](https://github.com/user-attachments/assets/f1b14dfd-aa47-4086-b3bd-39127f1b7887)

     2. If we taks the second Memory address 00000123C4620000 in the Memory Map view, to identify what the address is about, from the image we can understand the memory  	         allocated is private and the initial permission was Read Write and the new permission provided is ER-- after VirtualProtect is executed with new permission 

![image](https://github.com/user-attachments/assets/fb54f275-57ed-4dec-aea6-d06792f9b8e0)

     3. Now the final Memory address 00007FF743B0101E in Memory Map view, to identify where it is 

![image](https://github.com/user-attachments/assets/17c104ca-eebf-4c1d-9a07-f73644decda6)  



	Finally we understood the payload is saved in the .text section since the payload is placed in the main function as local variable. 
	Payload is saved in 
	1. Priv memory with proper permissions  
	2. Stack as local variable  
	3. .text Section     



	
 
 Next Would be working on Data Section

 @Sektor Learning










