  0000000000000000: 48 83 EC 68        sub         rsp,68h
  0000000000000004: 48 C7 04 24 FE FF  mov         qword ptr [rsp],0FFFFFFFFFFFFFFFEh
  000000000000000C: 0F 10 02           movups      xmm0,xmmword ptr [rdx]
  000000000000000F: 0F 11 01           movups      xmmword ptr [rcx],xmm0
  0000000000000012: 48 8B C1           mov         rax,rcx
  0000000000000015: 48 83 C4 68        add         rsp,68h
  0000000000000019: C3                 ret
