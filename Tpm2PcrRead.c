/*
 * Copyright (C) 2019 HPBirdChen (hpbirdtw@gmail.com)
 * All rights reserved.
 * The License file locate on:
 * https://github.com/HPBirdTW/ShellTpmDmpLog/license.txt
 * */

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include "ShellDmpLog2.h"

#pragma pack(1)
typedef struct
{
    TPM2_COMMAND_HEADER Header;
    TPML_PCR_SELECTION  pcrSelection;
}TPM2_PCR_Read;

typedef struct
{
    TPM2_RESPONSE_HEADER    ResHead;
    UINT32                  pcrUpdateCounter;
    TPML_PCR_SELECTION      pcrSelectionOut;
//    TPML_DIGEST             pcrValues;
}TPM2_PCR_Read_Res;

typedef struct {
  TPM2_COMMAND_HEADER       	Header;
  TPMI_DH_PCR               	PcrHandle;
  UINT32                    	AuthorizationSize;
  TPMS_AUTH_COMMAND 			AuthSessionPcr;
  TPML_DIGEST_VALUES        	DigestValues;
} TPM2_PCR_EXTEND_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER       	Header;
  UINT32                     	ParameterSize;
  TPMS_AUTH_RESPONSE 			AuthSessionPcr;
} TPM2_PCR_EXTEND_RESPONSE;


#pragma pack()

EFI_STATUS Tpm2ShaAlgoIdPCRRead(
    IN UINT16           AlgorithmId,
    IN TPM_PCRINDEX     PCRIndex,
    OUT UINT8*          Digest )
{
    EFI_STATUS              Status = EFI_SUCCESS;
    TPM2_PCR_Read           Cmd;
    UINTN                   unIdx;
    UINT32                  RetBufSize = 0x200;
    UINT8                   Res[0x200];
    TPM2_PCR_Read_Res       *pResCmd;
    TPML_DIGEST*            pRetDigest;

    SetMem( &Cmd, sizeof(Cmd), 0);

    Cmd.Header.tag         = (TPM_ST) SwapBytes16(TPM_ST_NO_SESSIONS);
    Cmd.Header.commandCode = (TPM_CC) SwapBytes32(TPM_CC_PCR_Read);
    
    Cmd.pcrSelection.count = SwapBytes32(0x00000001);
//    Cmd.pcrSelection.pcrSelections[0].hash = SwapBytes16(TPM_ALG_SHA1);    // SHA-1
    Cmd.pcrSelection.pcrSelections[0].hash = SwapBytes16(AlgorithmId);
    Cmd.pcrSelection.pcrSelections[0].sizeofSelect = (UINT8)PCR_SELECT_MIN;      // PCR 0~24 
    // Assign PCR Index.
    unIdx = PCRIndex / 8;
    Cmd.pcrSelection.pcrSelections[0].pcrSelect[unIdx] = (UINT8)1<<(PCRIndex % 8);
    
    Cmd.Header.paramSize = 
            sizeof(Cmd.Header)+ 
            sizeof(Cmd.pcrSelection.count)+
            sizeof(Cmd.pcrSelection.pcrSelections[0]);
        
    Cmd.Header.paramSize = SwapBytes32(Cmd.Header.paramSize);
    
    Status = Tpm2SubmitCommand(
            SwapBytes32(Cmd.Header.paramSize),
            (UINT8*)&Cmd,
            &RetBufSize,
            Res
            );
    if (EFI_ERROR (Status)) {
//       DEBUG((DEBUG_INFO,"Tpm2SubmitCommand() Failed: [%r]\n", Status));
       return Status;
   }
    
    pResCmd = (TPM2_PCR_Read_Res*)Res;
    
    if( pResCmd->ResHead.responseCode )
    {
//        DEBUG((DEBUG_INFO,"Tpm2PCRRead(...): ErrorCode[%x]\n", SwapBytes32(pResCmd->ResHead.responseCode) ));
        return EFI_DEVICE_ERROR;
    }
    
    // Here, need to extra check the pcr have also been selector.
    // 1. The pcrSelection count must be 1
    if (1 != SwapBytes32( pResCmd->pcrSelectionOut.count ) )
    {
        return EFI_DEVICE_ERROR;
    }
    // 2. must be the same algorithm
    if ( AlgorithmId != SwapBytes16(pResCmd->pcrSelectionOut.pcrSelections[0].hash))
    {
        return EFI_DEVICE_ERROR;
    }
    // 3. must match the same PcrIndex
    unIdx = PCRIndex / 8;
    if ((UINT8)1 << (PCRIndex % 8) != pResCmd->pcrSelectionOut.pcrSelections[0].pcrSelect[unIdx])
    {
        return EFI_DEVICE_ERROR;
    }

    // Presp
    unIdx = 
            // TPM2_RESPONSE_HEADER
            sizeof(pResCmd->ResHead) 
            // UINT32
            + sizeof(pResCmd->pcrUpdateCounter) 
            // UINT32
            + sizeof(pResCmd->pcrSelectionOut.count);
        
    unIdx += 
            // TPML_PCR_SELECTION->count * sizeof(TPMS_PCR_SELECTION)
            SwapBytes32(pResCmd->pcrSelectionOut.count) * sizeof(pResCmd->pcrSelectionOut.pcrSelections[0]);
    
    pRetDigest = (TPML_DIGEST*)&Res[unIdx];
        
    CopyMem( Digest, pRetDigest->digests[0].buffer, (UINTN)SwapBytes16(pRetDigest->digests[0].size));

    return Status;
}

EFI_STATUS Tpm2Sha1PCRRead(
    IN TPM_PCRINDEX     PCRIndex,
    OUT UINT8           *Digest )
{
    return Tpm2ShaAlgoIdPCRRead(
                                        TPM_ALG_SHA1,
                                        PCRIndex,
                                        Digest
                                        );
}

EFI_STATUS Tpm2Sha256PCRRead(
    IN TPM_PCRINDEX PCRIndex,
    OUT UINT8       *Digest )
{
    return Tpm2ShaAlgoIdPCRRead(
                                        TPM_ALG_SHA256,
                                        PCRIndex,
                                        Digest
                                        );
}

EFI_STATUS Tpm2Sha384PCRRead(
    IN TPM_PCRINDEX PCRIndex,
    OUT UINT8       *Digest )
{
    return Tpm2ShaAlgoIdPCRRead(
                                        TPM_ALG_SHA384,
                                        PCRIndex,
                                        Digest
                                        );
}

EFI_STATUS Tpm2Sha512PCRRead(
    IN TPM_PCRINDEX PCRIndex,
    OUT UINT8       *Digest )
{
    return Tpm2ShaAlgoIdPCRRead(
                                        TPM_ALG_SHA512,
                                        PCRIndex,
                                        Digest
                                        );
}

EFI_STATUS Tpm2Sm3_256PCRRead(
    IN TPM_PCRINDEX PCRIndex,
    OUT UINT8       *Digest )
{
    return Tpm2ShaAlgoIdPCRRead(
                                        TPM_ALG_SM3_256,
                                        PCRIndex,
                                        Digest
                                        );
}
