
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    
	void * exec_memory;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;

	// 4 byte payload since we are runing on 64bit
	unsigned char payload[] = {
		0x40,		// NOP
		0x90,		// NOP
		0xcc,		// INT3
		0xc3		// RET
	};
	unsigned int payload_len = 4;   // hard coded , we can use the sizeof function to get the length
	
	// Allocate a memory buffer for payload mentioned above
	exec_memory = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("%-20s : 0x%-016p\n", "payload addr", (void *)payload);
	printf("%-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_mem);

	// Copy payload to new buffer that is copy payload to exec_mem and lenght is payload_len
	RtlMoveMemory(exec_memory, payload, payload_len);
	
	// Make new buffer as executable so we can execute the code 
	rv = VirtualProtect(exec_memory, payload_len, PAGE_EXECUTE_READ, &oldprotect);

	printf("\nHit me!\n");
	getchar(); // wait as interrupt to check how the code is saved 

	// If all good, run the payload by creating a thread in the current process
	if ( rv != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_memory, 0, 0, 0);
			WaitForSingleObject(th, -1);
	}

	return 0;
}
