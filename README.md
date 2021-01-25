# Different Process Injections Implemented In C++

1. Classic (CreateRemoteThread):
  (Basic Process Injection which is very common now days)
  [] OpenProcess/CreateProcess: Get a handle to a running or newly created process.
  [] VirtualAllocEx: Allocate memory in the remote process.
  [] WriteProcessMemory: Write shellcode to the remote process.
  [] NtCreateThreadEx/RtlCreateUserThread/CreateRemoteThread: starts a thread in the remote process with the start address of the
  shellcode.
