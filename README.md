# directInjectorPOC

Small program written in C#, compatible with .NET >= v3.5 . Only x64. Works from ws 2008 up to the latest windows 10 update. 

Created as a way to learn more about direct syscalls and their implementation in C#. 

The program uses direct syscalls to perform the shellcode allocation/injection and the remote thread creation. 

The shellcode can be easily generated using tools like donut (https://github.com/TheWover/donut/)

### Update:
- Removed the sexy dictionaries that used to contained the syscalls:ssn
- The binary is now resolving the syscall ssn by using the sorting technique shown at https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/

### Usage: 

Shellcode alloc/injec methods: 
- ALLOCWRITE: Uses NtAllocateVirtualMemory and ZwWriteVirtualMemory to allocate and write the shellcode in the remote process
- OPENSEC: Uses NtCreateSection to create a new section and NtMapViewOfSection to map it to the local and remote process.

By default the program injects into "notepad" using the ALLOCWRITE write method. This can be easily modified by changing line 18 
```
Inject("notepad", osV, ALLOCWRITE);
```
can be changed to 
```
Inject("explorer", osV, OPENSEC);
```
to inject the shellcode into explorer.exe using the OPENSEC method. 

The shellcode must be in base64 and assigned to the "s" variable on line 91
```
//msf messagebox x64
string s = @"/EiB5PD////o0AAAAEFRQVBSUVZIMdJlSItSYD5Ii1IYPkiLUiA+SItyUD5ID7dKSk0xyUgxwKw8YXwCLCBBwckNQQHB4u1SQVE+SItSID6LQjxIAdA+i4CIAAAASIXAdG9IAdBQPotIGD5Ei0AgSQHQ41xI/8k+QYs0iEgB1k0xyUgxwKxBwckNQQHBOOB18T5MA0wkCEU50XXWWD5Ei0AkSQHQZj5BiwxIPkSLQBxJAdA+QYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVo+SIsS6Un///9dScfBAAAAAD5IjZX+AAAAPkyNhQMBAABIMclBukWDVgf/1UgxyUG68LWiVv/VZ2F0bwBNZXNzYWdlQm94AA==";
```


##### ToDo:

  - Add thread hijacking
  - Add more techniques to execute our syscall
  - Implement a syscall wrapper to prevent writing the syscall bytes directly to memory
            - Also look into ways to bypass potential manual syscalls detections, like looking where the syscalls returns to. 
            
  
##### Links of interest:

  - https://ired.team/offensive-security/code-injection-process-injection/ntcreatesection-+-ntmapviewofsection-code-injection
  - https://ired.team/offensive-security/code-injection-process-injection/process-injection
  - https://github.com/TheWover/donut/
  - https://github.com/b4rtik/SharpMiniDump/
  - https://github.com/outflanknl/Dumpert (tool)  https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/ (blog)


