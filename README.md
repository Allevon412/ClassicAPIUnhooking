# ClassicAPIUnhooking

This project is a simple Proof of Concept that unhooks EDR solutions from windows APIs using the classic map NTDLL.dll over the original DLL loaded into the processes' memory.

The payload executed is a simple message box shellcode that has been AES encrypted. It will be injected into the notepad process using the classic shellcode injection technique.
Not many attempts at obfuscation are made. All code was created by the Sektor7 Institute team, I simply created it into a VS project.
