.686

.model flat, C
option casemap :none

.data
lastHookAddress DWORD 0
lastESP DWORD 0

.code

	LIBHOOKDetourFunctionASM proc LIBHOOKGeneralHookFunc:DWORD
		POP EAX
		
		MOV lastESP, ESP

		;Prologue
		PUSH EDI
		PUSH EAX
		SUB ESP, 30H
	
		;Push the first arg of LIBHOOKGeneralHookFunc on the stack
		PUSH EAX
		CALL LIBHOOKGeneralHookFunc

		;Epilogue
		ADD ESP, 30H
		POP EAX
		POP EDI

		MOV lastHookAddress, EAX
		POP EAX

		;original function called
		JMP lastHookAddress 

	LIBHOOKDetourFunctionASM endp

	GetESP proc
		MOV EAX, lastESP
		RET
	GetESP endp

end
