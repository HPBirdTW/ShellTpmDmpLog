/*
 * Copyright (C) 2019 HPBirdChen (hpbirdtw@gmail.com)
 * All rights reserved.
 * The License file locate on:
 * https://github.com/HPBirdTW/ShellTpmDmpLog/license.txt
 * */

#ifndef __SHELL_TPM_DMPLOG2_H__
#define __SHELL_TPM_DMPLOG2_H__

#include <Protocol/TrEEProtocol.h>
#include <Protocol/TcgService.h>
#include "AuxFunc.h"
#include "Tpm2PcrRead.h"
#include "SM3.h"

#define BUILD_SHELL_TOOLS 1     // Build for Uefi Shell Application.

#if defined(SMDBG_SUPPORT_LIB) && SMDBG_SUPPORT_LIB
#undef DEBUG
    #define DEBUG(Arguments) SMDbgTrace Arguments
    #undef  ASSERT_EFI_ERROR
    #undef  ASSERT
    #define ASSERT(Condition) if(!(Condition)) { \
        SMDbgTrace((UINTN)-1,(CHAR8*)"ASSERT in %s on %i: %s\n",__FILE__, __LINE__, #Condition);\
        }
    #define ASSERT_EFI_ERROR(Status) ASSERT(!EFI_ERROR(Status))
#endif


#define STRUCT_FIELD_OFFSET( type, field )  \
    ((UINTN)&(((type*)0)->field))


#ifdef __cplusplus
extern "C" {
#endif

EFI_STATUS Sha1HashData(
    UINT8               *HashData,
    UINTN               HashDataLen,
    UINT8               *Digest
);

EFI_STATUS Sha256HashData(
    UINT8               *HashData,
    UINTN               HashDataLen,
    UINT8               *Digest
);

EFI_STATUS Sha384HashData(
    UINT8               *HashData,
    UINTN               HashDataLen,
    UINT8               *Digest
);

EFI_STATUS Sha512HashData(
    UINT8               *HashData,
    UINTN               HashDataLen,
    UINT8               *Digest
);

EFI_STATUS Sm3HashData(
    UINT8               *HashData,
    UINTN               HashDataLen,
    UINT8               *Digest
);

typedef struct {
  UINT8   Signature[16];
  UINT8   StartupLocality;
} TCG_EFI_STARTUP_LOCALITY_EVENT;

extern UINTN               g_EventStartAddr;
extern UINTN               g_EventEndAddr;

#ifndef EFI_TCG2_EVENT_LOG_FORMAT_TCG_2
#define EFI_TCG2_EVENT_LOG_FORMAT_TCG_2     0x00000002
#endif

#ifndef EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2
#define EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2   0x00000001
#endif

#ifndef EFI_TCG2_BOOT_HASH_ALG_SHA1
#define EFI_TCG2_BOOT_HASH_ALG_SHA1         0x00000001
#endif

#ifndef EFI_TCG2_BOOT_HASH_ALG_SHA256
#define EFI_TCG2_BOOT_HASH_ALG_SHA256       0x00000002
#endif

#ifndef EFI_TCG2_BOOT_HASH_ALG_SHA384
#define EFI_TCG2_BOOT_HASH_ALG_SHA384       0x00000004
#endif

#ifndef EFI_TCG2_BOOT_HASH_ALG_SHA512
#define EFI_TCG2_BOOT_HASH_ALG_SHA512       0x00000008
#endif

#ifndef EFI_TCG2_BOOT_HASH_ALG_SM3_256
#define EFI_TCG2_BOOT_HASH_ALG_SM3_256      0x00000010
#endif

/****** DO NOT WRITE BELOW THIS LINE *******/
#ifdef __cplusplus
}
#endif
#endif

