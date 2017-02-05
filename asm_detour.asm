
extern printf : proc
extern LIBHOOKGeneralHookFunc : proc

; REMEMBER :
; don't use passed variable names!
; MASM doesn't support this for x64


.data
lastHookAddress dq 0
lastRCX dq 0
lastRDX dq 0
lastR8 dq 0
lastR9 dq 0
lastRSP dq 0


.code

	LIBHOOKDetourFunctionx64 proc
		POP RAX
		

		MOV lastRCX, RCX
		MOV lastRDX, RDX
		MOV lastR8, R8
		MOV lastR9, R9
		MOV lastRSP, RSP

		;Prologue
		PUSH RDI
		PUSH RAX
		PUSH RDX
		PUSH RCX
		PUSH R8
		PUSH R9
		SUB RSP, 20H
	
		MOV RCX, RAX
		CALL LIBHOOKGeneralHookFunc

		;Epilogue
		ADD RSP, 20H
		POP R9
		POP R8
		POP RCX
		POP RDX
		POP RAX
		POP RDI

		MOV lastHookAddress, RAX
		POP RAX

		JMP lastHookAddress ;original function called

	LIBHOOKDetourFunctionx64 endp

	GetRSPx64 proc
		MOV RAX, lastRSP
		RET
	GetRSPx64 endp

	GetRCXx64 proc
		MOV RAX, lastRCX
		RET
	GetRCXx64 endp

	GetRDXx64 proc
		MOV RAX, lastRDX
		RET
	GetRDXx64 endp

	GetR8x64 proc
		MOV RAX, lastR8
		RET
	GetR8x64 endp

	GetR9x64 proc
		MOV RAX, lastR9
		RET
	GetR9x64 endp

end
