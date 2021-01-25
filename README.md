# Different Process Injections Implemented In C++

**[Basic process injection, detected by most EDP and anti-virus software]**
* Classic (CreateRemoteThread):
  * OpenProcess/CreateProcess: Get a handle to a running or newly created process.
  * VirtualAllocEx: Allocate memory in the remote process.
  * WriteProcessMemory: Write shellcode to the remote process.
  * NtCreateThreadEx/RtlCreateUserThread/CreateRemoteThread: starts a thread in the remote process with the start address of the shellcode.

