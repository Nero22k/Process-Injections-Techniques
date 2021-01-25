# Different Process Injections Implemented In C++

**[Basic process injection, detected by most EDP and anti-virus software]**
* Classic (CreateRemoteThread):
  * OpenProcess/CreateProcess: Get a handle to a running or newly created process.
  * VirtualAllocEx: Allocate memory in the remote process.
  * WriteProcessMemory: Write shellcode to the remote process.
  * NtCreateThreadEx/RtlCreateUserThread/CreateRemoteThread: starts a thread in the remote process with the start address of the shellcode.

**[ThreadHijacking injection, targets an existing thread of a process and avoids any noisy process or thread creations operations. Bypasses some anti-virus solutions]**
***This technique often results in crashing the target process***
* ThreadHijacking (SuspendThread):
  * SuspendThread: Suspend the thread we want to hijack.
  * OpenProcess: Get a handle to a running process.
  * CreateToolhelp32Snapshot: create a snapshot of target process threads.
  * VirtualAllocEx: Allocate memory in the remote process.
  * WriteProcessMemory: Write shellcode to the remote process.
  * GetThreadContext: Retrieve the current thread context.
  * SetThreadContext: Update instruction point for thread to shellcode.
  * ResumeThread: Resume the hijacked thread.
