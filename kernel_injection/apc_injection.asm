.code

InjectorAPCNormalRoutine proc

	push    rbx
	
	sub     rsp,30h
	
	mov     rax,qword ptr [rcx+10h]
	
	lea     r9,[rsp+40h]
	
	mov     rbx,rcx
	
	mov     r8,rcx
	
	xor     ecx,ecx
	
	xor     edx,edx
	
	call    rax
	
	mov     dword ptr [rbx+20h],1
	
	add     rsp,30h
	
	pop     rbx
	
	ret

InjectorAPCNormalRoutine endp

end