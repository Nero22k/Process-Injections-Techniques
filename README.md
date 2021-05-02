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

**[MapView process injection, shares a section view with a target process then spawns new thread and executes the payload inside the process. Can be used for AV evasion]**
* MapView (NtMapViewOfSection):
  * NtCreateSection: Creates new section that is shared between the process.
  * NtMapViewOfSection: Create a local section view.
  * memcpy: Copy the paylod in the section.
  * NtMapViewOfSection: Create remote section view.
  * RtlCreateUserThread: Create a remote thread in the target process and point it to the mapped view in the target process to trigger the shellcode
  
**[APC (Asynchronous Procedure Calls) queue code injection - Payload is executed when process enters into alertable state]**
* APC Queue (QueueUserAPC):
  * VirtualAllocEx: Allocate memory in the remote process.
  * WriteProcessMemory: Write shellcode to the remote process.
  * OpenProcess: Get a handle to a running process.
  * QueueUserAPC: Adds async procedure call (APC) object to thread's APC queue
  * CreateToolhelp32Snapshot: create a snapshot of target process threads.
