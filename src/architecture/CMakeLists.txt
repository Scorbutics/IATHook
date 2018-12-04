cmake_minimum_required(VERSION 3.9)
project(iathook_architecture_dependent)

if(NOT HOOK_PLATFORM)
	message(WARNING "HOOK_PLATFORM is not defined : assuming we are in x86 mode...")
	set(HOOK_PLATFORM "x86")
endif()

if(NOT HOOK_ASM)
	IF (WIN32)
	  set(HOOK_ASM "MASM")
	ELSE()
	  set(HOOK_ASM "ATT")
	ENDIF()
	message(WARNING "HOOK_ASM is not defined : assuming we are using ${HOOK_ASM} ...")
endif()

if(HOOK_ASM STREQUAL "MASM")
	ENABLE_LANGUAGE(ASM_MASM)
elseif(HOOK_ASM STREQUAL "ATT")
	ENABLE_LANGUAGE(ASM-ATT)
else()
	message(ERROR "Bad HOOK_ASM value : ${HOOK_ASM}")
endif()

file(GLOB_RECURSE SOURCES
	src/${HOOK_ASM}/${HOOK_PLATFORM}/*.asm
)

string(REGEX REPLACE "[^;]*CMakeFiles/[^;]+;?" "" SOURCES "${SOURCES}")

add_library(iathook_architecture_dependent STATIC ${SOURCES})

