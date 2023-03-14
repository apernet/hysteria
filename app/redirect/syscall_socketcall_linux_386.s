//go:build gc
// +build gc

#include "textflag.h"

TEXT ·syscall_socketcall(SB),NOSPLIT,$0-36
	JMP	syscall·socketcall(SB)
