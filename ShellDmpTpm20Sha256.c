#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include "ShellDmpLog2.h"

typedef VOID (*tdTpmtHaProc)(UINT8* pTpmtHa, VOID* CallBackContext);

EFI_STATUS Tpm2GetCapPCRs(
    UINT32  *pSupportedPcrBitMap,
    UINT32  *pActivePcrBitMap
);

UINTN GetSize_TpmpHa(UINT8* pStart, UINT8** pNext, tdTpmtHaProc TpmtHaProc, VOID *CallBackContext)
{
    UINT8*      pBuf = pStart;
    UINTN       DigestSize;
    UINT16      AlgorithmId;

    AlgorithmId = *(UINT16*)pBuf;

    switch (AlgorithmId)
    {
        case TPM_ALG_SHA1:
            DigestSize = SHA1_DIGEST_SIZE;
        break;
        case  TPM_ALG_SHA256:
            DigestSize = SHA256_DIGEST_SIZE;
        break;
        case TPM_ALG_SHA384:
            DigestSize = SHA384_DIGEST_SIZE;
        break;
        case TPM_ALG_SHA512:
            DigestSize = SHA512_DIGEST_SIZE;
        break;
        case TPM_ALG_SM3_256:
            DigestSize = SM3_256_DIGEST_SIZE;
        break;
        default:
            DigestSize = -1;
            // The Digest AlgorithmId Err.
            return -1;
        break;
    }

    if( TpmtHaProc )
    {
        TpmtHaProc (pStart, CallBackContext);
    }

    pBuf += sizeof(UINT16);     // AlgorithmId
    pBuf += DigestSize;         // Digest

    *pNext = pBuf;

    return (UINTN)( pBuf - pStart );

}

UINTN GetSize_TpmlDigestValues( UINT8* pStart, UINT8** pNext, tdTpmtHaProc TpmtHaProc, VOID *CallBackContext )
{
    UINT8*      pBuf = pStart;
    UINTN       unIdx;
    UINTN       Count;

    Count = *(UINT32*)pBuf;
    pBuf += sizeof(UINT32);     // Count

    for (unIdx=0; unIdx<Count; ++unIdx)
    {
        if ( -1 == GetSize_TpmpHa (pBuf, &pBuf, TpmtHaProc, CallBackContext))
        {
            // The Struct Parsing Err.
            return -1;
        }
    }

    *pNext = pBuf;

    return (UINTN)( pBuf - pStart );
}

EFI_STATUS  ChkTpm2tartupLocalityEvent( UINT8* pStart, UINTN *Locality)
{
    UINT8*          pBuf = pStart;
    EFI_STATUS      Status = EFI_SUCCESS;
    CONST UINT8     StartLocality[] = "StartupLocality";

    EFI_STATUS GetNextSMLEvent(TCG_PCR_EVENT* pStart, TCG_PCR_EVENT** pNext);

    if( ((TCG_PCR_EVENT*)pStart)->EventType == 0x03 && pStart == (UINT8*)g_EventStartAddr ) // EV_NO_ACTION
    {
        return EFI_NOT_FOUND;
    }

    if( *(UINT32*)pBuf != 0  )
    {
        return EFI_NOT_FOUND;
    }
    pBuf += sizeof(UINT32);    // PCRIndex

    if( *(UINT32*)pBuf != 3  )
    {
        return EFI_NOT_FOUND;
    }
    pBuf += sizeof(UINT32);    // EventType

    if( -1 == GetSize_TpmlDigestValues (pBuf, &pBuf, NULL, NULL) )    // Digests
    {
        // The Struct Detect Err.
        return EFI_NOT_FOUND;
    }

    if( *(UINT32*)pBuf != sizeof(TCG_EFI_STARTUP_LOCALITY_EVENT)  )
    {
        return EFI_NOT_FOUND;
    }
    pBuf += sizeof(UINT32);     // EventSize

    if( 0 != CompareMem (((TCG_EFI_STARTUP_LOCALITY_EVENT*)pBuf)->Signature, StartLocality, sizeof(StartLocality)) )
    {
        return EFI_NOT_FOUND;
    }

    *Locality = (UINTN)((TCG_EFI_STARTUP_LOCALITY_EVENT*)pBuf)->StartupLocality;

    return EFI_SUCCESS;
}

UINTN  GetSize_TCG_PCR_EVENT2( UINT8* pStart, UINT8** pNext, tdTpmtHaProc TpmtHaProc, VOID *CallBackContext  )
{
    UINT8*          pBuf = pStart;
    UINTN           EventSize = 0;
    EFI_STATUS      Status;
    EFI_STATUS GetNextSMLEvent(TCG_PCR_EVENT* pStart, TCG_PCR_EVENT** pNext);

    if ( ((TCG_PCR_EVENT*)pStart)->EventType == 0x03 && pStart == (UINT8*)g_EventStartAddr ) // EV_NO_ACTION
    {
        Status = GetNextSMLEvent ((TCG_PCR_EVENT*)pStart, (TCG_PCR_EVENT**)pNext );
        if( EFI_ERROR(Status) )
            return -1;

        return (UINTN)( (*pNext) - pStart );
    }

    pBuf += sizeof(UINT32);    // PCRIndex
    pBuf += sizeof(UINT32);    // EventType

    if( -1 == GetSize_TpmlDigestValues (pBuf, &pBuf, TpmtHaProc, CallBackContext ) )    // Digests
    {
        // The Struct Detect Err.
        return -1;
    }

    EventSize = *(UINT32*)pBuf;
    pBuf += sizeof(UINT32);     // EventSize

    pBuf += EventSize;          // EventData

    *pNext = pBuf;

    return (UINTN)( pBuf - pStart );

}

VOID PrintTpmHa( UINT8* pTpmtHa, VOID* CallBackContext )
{
    UINT8*      pBuf = pTpmtHa;
    UINTN       DigestSize;
    UINT16      AlgorithmId;

    AlgorithmId = *(UINT16*)pBuf;

    switch( AlgorithmId )
    {
        case TPM_ALG_SHA1:
            DigestSize = SHA1_DIGEST_SIZE;
        break;
        case  TPM_ALG_SHA256:
            DigestSize = SHA256_DIGEST_SIZE;
        break;
        case TPM_ALG_SHA384:
            DigestSize = SHA384_DIGEST_SIZE;
        break;
        case TPM_ALG_SHA512:
            DigestSize = SHA512_DIGEST_SIZE;
        break;
        case TPM_ALG_SM3_256:
            DigestSize = SM3_256_DIGEST_SIZE;
        break;
        default:
            DigestSize = -1;
            // The Digest AlgorithmId Err.
            return;
        break;
    }
    SPrintf (L"AlgorithmId:");
    SPrintBuf (sizeof(UINT16), pBuf);
    pBuf += sizeof(UINT16);

    SPrintf (L"Digest:" );
    SPrintBuf (DigestSize, pBuf);
}

EFI_STATUS TCG_PCR_EVENT2_PrintOneEvent(UINT8* pStart, UINT8** pNext )
{
    UINT8*          pBuf = pStart;
    UINTN           unIdx = 0;
    UINTN           EventSize;
    TCG_PCR_EVENT*  pTcgPcrEvent = (TCG_PCR_EVENT*)pStart;

    EFI_STATUS TCG_PCR_EVENT_PrintOneEvent(TCG_PCR_EVENT* pStart, TCG_PCR_EVENT** pNext);

    if (!pTcgPcrEvent->EventType)
        return EFI_NOT_FOUND;

    if (pTcgPcrEvent->EventType == 0x03 && pStart==(UINT8*)g_EventStartAddr ) // EV_NO_ACTION
    {
//        SPrintf( L"First Event Log\n\r", (UINTN)pBuf );
        return TCG_PCR_EVENT_PrintOneEvent ((TCG_PCR_EVENT*)pStart, (TCG_PCR_EVENT**)pNext);
    }

    if (-1 == GetSize_TCG_PCR_EVENT2 (pStart, pNext, NULL, NULL) )
    {
        return EFI_OUT_OF_RESOURCES;
    }

    SPrintf (L"Event Addr: [%08x]\n\r", (UINTN)pBuf);

    SPrintf (L"PCRIndex  : [%08x]\n\r", (UINTN)pTcgPcrEvent->PCRIndex);
    pBuf += sizeof(UINT32);

    SPrintf (L"EventType : [%08x]\n\r", (UINTN)pTcgPcrEvent->EventType);
    pBuf += sizeof(UINT32);

    // Print AlgorithmID, Digest
    GetSize_TpmlDigestValues (pBuf, &pBuf, PrintTpmHa, NULL);

    EventSize = *(UINT32*)pBuf;
    SPrintf (L"EventData: Size[%04x]", EventSize );
    pBuf += sizeof(UINT32);
    SPrintBufMixChar (EventSize, pBuf);
    SPrintf (L"\n\r");

    return EFI_SUCCESS;
}

EFI_STATUS Tpm2CryptoAgileDmpLog( VOID )
{
    EFI_STATUS                      Status = EFI_SUCCESS;
    UINT8*                          pNext = NULL;
    UINTN                           unEventCount = 0;
    EFI_TREE_PROTOCOL               *TreeProtocol;
    EFI_PHYSICAL_ADDRESS            EventStartAddr = 0;
    EFI_PHYSICAL_ADDRESS            EventEndAddr = 0;
    BOOLEAN                         bLogTruncated = FALSE;
    UINT8                           u8Buf[0x100];
    TREE_BOOT_SERVICE_CAPABILITY    *pCap = NULL;

//    DEBUG((-1,"Enter Tpm2CryptoAgileDmpLog(...)\n"));

    do
    {
        Status = gBS->LocateProtocol (&gEfiTrEEProtocolGuid, NULL, (VOID **) &TreeProtocol);
        if (EFI_ERROR (Status)) {
            PString (L"Can not Locate[gEfiTrEEProtocolGuid]. Failed.\n\r");
            break;
        }

        SetMem( u8Buf, sizeof(u8Buf), 0);
        pCap = (TREE_BOOT_SERVICE_CAPABILITY*)&u8Buf[0];
        pCap->Size = 0xFF;

        Status = TreeProtocol->GetCapability (TreeProtocol, pCap );
        if (EFI_ERROR (Status))
        {
            SPrintf (L"Failed Get TreeProtocol->GetCapability(...) -%r [%x]\n\r", Status, Status);
            break;
        }

        if (0 == (pCap->SupportedEventLogs & EFI_TCG2_EVENT_LOG_FORMAT_TCG_2))
        {
            Status = EFI_NOT_FOUND;
            break;
        }

        Status = TreeProtocol->GetEventLog (TreeProtocol,
                                            EFI_TCG2_EVENT_LOG_FORMAT_TCG_2,
                                            &EventStartAddr,
                                            &EventEndAddr,
                                            &bLogTruncated );
        if( EFI_ERROR(Status) )
        {
            SPrintf (L"Failed Get TreeProtocol->GetEventLog(...) -%r [%x]\n\r", Status, Status);
            break;
        }

        SPrintf (L"\n\rGet TreeProtocol->GetEventLog (...)\n\r");
        SPrintf (L"    EventLogLocation     [%x]\n\r", (UINTN)EventStartAddr);
        SPrintf (L"    EventLogLastEntry    [%x]\n\r", (UINTN)EventEndAddr );
        SPrintf (L"    EventLogTruncated    [%x]\n\r", bLogTruncated == TRUE ? 0x01 : 0x00);

        g_EventStartAddr = (UINTN)EventStartAddr;
        g_EventEndAddr = (UINTN)EventEndAddr;

        SPrintf (L"\n\rTpm20 Crypto Agile Log Event(...)\n\r");
        pNext = (UINT8*)EventStartAddr;
        do {
            if( 0 == (UINTN)EventEndAddr )
            {
                SPrintf (L"Get Empty Event log\n\r");
                break;
            }

            ++unEventCount;

            if( (UINTN)pNext >= (UINTN)EventEndAddr )
            {
                if(  (UINTN)pNext == (UINTN)EventEndAddr )
                {
                    TCG_PCR_EVENT2_PrintOneEvent (pNext, &pNext);
                }
                SPrintf (L"End of the Event Log, Total Count [0x%d]\n\r", unEventCount);
                break;
            }
        } while (EFI_SUCCESS == (Status = TCG_PCR_EVENT2_PrintOneEvent ( pNext, &pNext )) );

    } while (FALSE);

    return Status;
}

VOID GetDigestFromTpmHa( UINT8* pTpmtHa, VOID* CallBackContext, UINT16 HashAlgID )
{
    UINT8*      pBuf = pTpmtHa;
    UINT8*      pDigest = (UINT8*)CallBackContext;
    UINTN       DigestSize;
    UINT16      AlgorithmId;

    AlgorithmId = *(UINT16*)pBuf;

    switch( AlgorithmId )
    {
        case TPM_ALG_SHA1:
            DigestSize = SHA1_DIGEST_SIZE;
        break;
        case  TPM_ALG_SHA256:
            DigestSize = SHA256_DIGEST_SIZE;
        break;
        case TPM_ALG_SHA384:
            DigestSize = SHA384_DIGEST_SIZE;
        break;
        case TPM_ALG_SHA512:
            DigestSize = SHA512_DIGEST_SIZE;
        break;
        case TPM_ALG_SM3_256:
            DigestSize = SM3_256_DIGEST_SIZE;
        break;
        default:
            DigestSize = -1;
            // The Digest AlgorithmId Err.
            return;
        break;
    }

    pBuf += sizeof(UINT16);

    if( HashAlgID == AlgorithmId )
    {
        CopyMem (pDigest, pBuf, DigestSize);
    }
}

VOID GetSm3_256DigestFromTpmHa( UINT8* pTpmtHa, VOID* CallBackContext )
{
    GetDigestFromTpmHa (pTpmtHa, CallBackContext, TPM_ALG_SM3_256);
    return;
}

VOID GetSha256DigestFromTpmHa( UINT8* pTpmtHa, VOID* CallBackContext )
{
    GetDigestFromTpmHa (pTpmtHa, CallBackContext, TPM_ALG_SHA256);
    return;
}

VOID GetSha384DigestFromTpmHa( UINT8* pTpmtHa, VOID* CallBackContext )
{
    GetDigestFromTpmHa (pTpmtHa, CallBackContext, TPM_ALG_SHA384);
    return;
}

VOID GetSha512DigestFromTpmHa( UINT8* pTpmtHa, VOID* CallBackContext )
{
    GetDigestFromTpmHa (pTpmtHa, CallBackContext, TPM_ALG_SHA512);
    return;
}

VOID GetSha1DigestFromTpmHa( UINT8* pTpmtHa, VOID* CallBackContext )
{
    GetDigestFromTpmHa (pTpmtHa, CallBackContext, TPM_ALG_SHA1);
    return;
}

EFI_STATUS CalcSMLTpm20HashPCR(
    UINT16          HashAlgorithmID
)
{

    EFI_STATUS              Status;
    UINT8                   EvaDigest[SHA512_DIGEST_SIZE * 2];
    UINT8                   HashVal[SHA512_DIGEST_SIZE];
    UINT8                   pcrValue[SHA512_DIGEST_SIZE];
    UINT8                   EmptyDigest[SHA512_DIGEST_SIZE];
    UINT32                  unPCRIdx = 0;
    UINT32                  unCurEventPcr = 0;
    UINT8*                  pNext = NULL;
    EFI_TREE_PROTOCOL       *TreeProtocol;
    EFI_PHYSICAL_ADDRESS    EventStartAddr = 0;
    EFI_PHYSICAL_ADDRESS    EventEndAddr = 0;
    BOOLEAN                 bLogTruncated = FALSE;
    UINTN                   Locality = 0;
    UINTN                   HashBlockLen = 0;
    tdTpmtHaProc            pTpmtHaFunc = NULL;
    EFI_STATUS              (*HashFunc)(UINT8* Buf, UINTN BufLen, UINT8* mac);

    do
    {
        Status = gBS->LocateProtocol (&gEfiTrEEProtocolGuid, NULL, (VOID **) &TreeProtocol);
        if (EFI_ERROR (Status)) {
            PString(L"Can not Locate[gEfiTrEEProtocolGuid]. Failed.\n\r");
            break;
        }

        Status = TreeProtocol->GetEventLog (TreeProtocol,
                                            EFI_TCG2_EVENT_LOG_FORMAT_TCG_2,
                                            &EventStartAddr,
                                            &EventEndAddr,
                                            &bLogTruncated );
        if (EFI_ERROR(Status))
        {
            SPrintf (L"Failed Get TreeProtocol->GetEventLog(...) -%r [%x]\n\r", Status, Status);
            break;
        }

        if (0 == EventStartAddr || 0 == EventEndAddr)
        {
            Status = EFI_INVALID_PARAMETER;
            SPrintf (L"Invalid parameter of (EventLogLocation | EventLogLastEntry)\n\r");
            break;
        }

        switch (HashAlgorithmID)
        {
            case TPM_ALG_SHA1:
                HashBlockLen = SHA1_DIGEST_SIZE;
                pTpmtHaFunc = GetSha1DigestFromTpmHa;
                HashFunc = Sha1HashData;
                break;
            case TPM_ALG_SHA256:
                HashBlockLen = SHA256_DIGEST_SIZE;
                pTpmtHaFunc = GetSha256DigestFromTpmHa;
                HashFunc = Sha256HashData;
                break;
            case TPM_ALG_SHA384:
                HashBlockLen = SHA384_DIGEST_SIZE;
                pTpmtHaFunc = GetSha384DigestFromTpmHa;
                HashFunc = Sha384HashData;
                break;
            case TPM_ALG_SHA512:
                HashBlockLen = SHA512_DIGEST_SIZE;
                pTpmtHaFunc = GetSha512DigestFromTpmHa;
                HashFunc = Sha512HashData;
                break;
            case TPM_ALG_SM3_256:
                HashBlockLen = SM3_256_DIGEST_SIZE;
                pTpmtHaFunc = GetSm3_256DigestFromTpmHa;
                HashFunc = Sm3HashData;
                break;
        }

        g_EventStartAddr = (UINTN)EventStartAddr;
        g_EventEndAddr = (UINTN)EventEndAddr;

__RepCheck:
        SetMem (EvaDigest, sizeof(EvaDigest), 0);
        SetMem (EmptyDigest, sizeof(EmptyDigest), 0);
        SetMem (HashVal, sizeof(HashVal), 0);
        // Initialize.
        pNext = (UINT8*)EventStartAddr;

        do
        {
            SetMem (&EvaDigest[HashBlockLen], HashBlockLen, 0);
            unCurEventPcr = ((TCG_PCR_EVENT*)pNext)->PCRIndex;

            Status = ChkTpm2tartupLocalityEvent (pNext, &Locality);
            if( !EFI_ERROR (Status) && unPCRIdx == 0)
            {
                EvaDigest[HashBlockLen-1] = (UINT8)Locality;
            }

            if( -1 == GetSize_TCG_PCR_EVENT2 (pNext, &pNext, pTpmtHaFunc, &EvaDigest[HashBlockLen]) )
                break;

            if( CompareMem (&EvaDigest[HashBlockLen], EmptyDigest, HashBlockLen) && unPCRIdx == unCurEventPcr)
            {
                HashFunc ((UINT8*)(UINTN)&EvaDigest, HashBlockLen * 2, &HashVal[0]);
                CopyMem (&EvaDigest[0], &HashVal[0], HashBlockLen);
            }
        }  while ((UINTN)pNext <= (UINTN)EventEndAddr);

        SPrintf (L"\n\rEVA_VALUE[%02x]", (UINTN)unPCRIdx);
        SPrintBuf (HashBlockLen, &HashVal[0]);

        SetMem (&pcrValue[0], HashBlockLen, 0);
        Status = Tpm2ShaAlgoIdPCRRead ( HashAlgorithmID, unPCRIdx, &pcrValue[0]);
        if (EFI_ERROR (Status))
        {
            SPrintf (L"Fail to Get TPM PCRIndex[%02x] - %r", (UINTN)unPCRIdx, Status );
        }
        else
        {
            SPrintf (L"PCR_VALUE[%02x]", (UINTN)unPCRIdx );
            SPrintBuf ( HashBlockLen, &pcrValue[0]);
        }

        if( ++unPCRIdx <= 7 )
            goto __RepCheck;

    } while (FALSE);

    return Status;
}

EFI_STATUS ShowSMLTpm20HashPCR (VOID)
{
    EFI_STATUS              Status = EFI_SUCCESS;
    UINT32                  SupportPcrBank;
    UINT32                  ActivePcrBank;
    EFI_TREE_PROTOCOL       *TreeProtocol;
    EFI_PHYSICAL_ADDRESS    EventStartAddr = 0;
    EFI_PHYSICAL_ADDRESS    EventEndAddr = 0;
    BOOLEAN                 bLogTruncated = FALSE;
    UINT8                           u8Buf[0x100];
    TREE_BOOT_SERVICE_CAPABILITY    *pCap = NULL;

    do
    {
        Status = gBS->LocateProtocol (&gEfiTrEEProtocolGuid, NULL, (VOID **) &TreeProtocol);
        if (EFI_ERROR (Status)) {
            PString(L"Can not Locate[gEfiTrEEProtocolGuid]. Failed.\n\r");
            break;
        }

        SetMem ( u8Buf, sizeof(u8Buf), 0);
        pCap = (TREE_BOOT_SERVICE_CAPABILITY*)&u8Buf[0];
        pCap->Size = 0xFF;

        Status = TreeProtocol->GetCapability( TreeProtocol, pCap );
        if (EFI_ERROR (Status))
        {
            SPrintf (L"Failed Get TreeProtocol->GetCapability(...) -%r [%x]\n\r", Status, Status);
            break;
        }

        if (0 == (pCap->SupportedEventLogs | EFI_TCG2_EVENT_LOG_FORMAT_TCG_2))
        {
            Status = EFI_NOT_FOUND;
            break;
        }

        Status = Tpm2CryptoAgileDmpLog ();
        if (EFI_ERROR (Status))
        {
            SPrintf (L"Failed on Dump TPM2 Crypto Agile Log Event. -%r [%x]\n\r", Status, Status);
            break;
        }

        Status = Tpm2GetCapPCRs (&SupportPcrBank, &ActivePcrBank);
        if (EFI_ERROR(Status) )
        {
            SPrintf (L"Failed Get TPM 2.0 Device PCR Bank. -%r [%x]\n\r", Status, Status);
            break;
        }

        SPrintf (L"Tpm2GetCapPCRs(...), BitMap[0..4]:[SHA1 | SHA256 | SHA384 | SHA512 | SM3]\n\r");
        SPrintf (L"    SupportPcrBank   [0x%08x]\n\r", (UINTN)SupportPcrBank);
        SPrintf (L"    ActivePcrBank    [0x%08x]\n\r", (UINTN)ActivePcrBank);

        if (!EFI_ERROR (Status) && (ActivePcrBank & EFI_TCG2_BOOT_HASH_ALG_SHA1))
        {
            SPrintf (L"Check SHA1 EventLog and TPM SHA1 PCR:");
            Status = CalcSMLTpm20HashPCR (TPM_ALG_SHA1);
            SPrintf (L"\n\r");
        }
        if (!EFI_ERROR (Status) && (ActivePcrBank & EFI_TCG2_BOOT_HASH_ALG_SHA256))
        {
            SPrintf (L"Check SHA256 EventLog and TPM SHA256 PCR:");
            Status = CalcSMLTpm20HashPCR (TPM_ALG_SHA256);
            SPrintf (L"\n\r");
        }
        if (!EFI_ERROR (Status) && (ActivePcrBank & EFI_TCG2_BOOT_HASH_ALG_SHA384))
        {
            SPrintf (L"Check SHA384 EventLog and TPM SHA384 PCR:");
            Status = CalcSMLTpm20HashPCR (TPM_ALG_SHA384);
            SPrintf (L"\n\r");
        }
        if (!EFI_ERROR (Status) && (ActivePcrBank & EFI_TCG2_BOOT_HASH_ALG_SHA512))
        {
            SPrintf (L"Check SHA512 EventLog and TPM SHA512 PCR:");
            Status = CalcSMLTpm20HashPCR (TPM_ALG_SHA512);
            SPrintf (L"\n\r");
        }
        if (!EFI_ERROR (Status) && (ActivePcrBank & EFI_TCG2_BOOT_HASH_ALG_SM3_256))
        {
            SPrintf (L"Check SM3_256 EventLog and TPM SM3_256 PCR:");
            Status = CalcSMLTpm20HashPCR (TPM_ALG_SM3_256);
            SPrintf (L"\n\r");
        }
        if (EFI_ERROR (Status))
        {
            // Failed to calculate SML PCR expect value or get TPM PCR value.
            break;
        }

    } while (FALSE);

    return Status;
}

#pragma pack(1)
typedef struct {
  TPM2_COMMAND_HEADER       Header;
  TPM_CAP                   Capability;
  UINT32                    Property;
  UINT32                    PropertyCount;
} TPM2_GET_CAPABILITY_COMMAND;

typedef struct {
  TPM2_RESPONSE_HEADER      Header;
  TPMI_YES_NO               MoreData;
  TPMS_CAPABILITY_DATA      CapabilityData;
} TPM2_GET_CAPABILITY_RESPONSE;
#pragma pack()

EFI_STATUS
EFIAPI
Tpm2GetCapability (
    TPM_CAP                 Capability,
    UINT32                  Property,
    UINT32                  PropertyCount,
    TPMI_YES_NO             *MoreData,
    TPMS_CAPABILITY_DATA    *CapabilityData
)
{
  EFI_STATUS                        Status;
  TPM2_GET_CAPABILITY_COMMAND       SendBuffer;
  TPM2_GET_CAPABILITY_RESPONSE      RecvBuffer;
  UINT32                            SendBufferSize;
  UINT32                            RecvBufferSize;


  SendBuffer.Header.tag = SwapBytes16 (TPM_ST_NO_SESSIONS);
  SendBuffer.Header.commandCode = SwapBytes32 (TPM_CC_GetCapability);

  SendBuffer.Capability = SwapBytes32 (Capability);
  SendBuffer.Property = SwapBytes32 (Property);
  SendBuffer.PropertyCount = SwapBytes32 (PropertyCount);

  SendBufferSize = (UINT32) sizeof (SendBuffer);
  SendBuffer.Header.paramSize = SwapBytes32 (SendBufferSize);

  //
  // send Tpm command
  //
  RecvBufferSize = sizeof (RecvBuffer);
  Status = Tpm2SubmitCommand (SendBufferSize, (UINT8 *)&SendBuffer, &RecvBufferSize, (UINT8 *)&RecvBuffer );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (RecvBufferSize <= sizeof (TPM2_RESPONSE_HEADER) + sizeof (UINT8)) {
    return EFI_DEVICE_ERROR;
  }

  if( RecvBuffer.Header.responseCode )
  {
      Status = SwapBytes32 (RecvBuffer.Header.responseCode) | (RETURN_STATUS)MAX_BIT ;
      return Status;
  }

  //
  // Return the response
  //
  *MoreData = RecvBuffer.MoreData;
  //
  // Does not unpack all possiable property here, the caller should unpack it and note the byte order.
  //
  CopyMem (CapabilityData, &RecvBuffer.CapabilityData, RecvBufferSize - sizeof (TPM2_RESPONSE_HEADER) - sizeof (UINT8));

  return EFI_SUCCESS;
}

EFI_STATUS
Tpm2GetSupportPcrBank (
    UINT32      *SupportHashAlg
)
{
    UINT8       Tpm2CapAlgs [] = { \
                        0x80, 0x01, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x01, 0x7a,     \
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,                 \
                        0x00, 0x00, 0x00, 0x64                                          \
                    };

    UINT8           TpmRespBuf [0x200];
    EFI_STATUS      Status = EFI_SUCCESS;
    UINT32          u32TmpVal = 0;
    UINTN           Count;
    UINTN           Index = 0;
    UINT16          AlgID = 0;
    UINT32          AlgProperties;
    UINT8           *pByte = NULL;
    UINT32          AlgPcrSupport;
    UINT32          RecvBufferSize;

//    DEBUG (( DEBUG_INFO, "[%d]: Enter Tpm2GetSupportPcrBank ()\n", __LINE__));

    do
    {
        // Get the CAP_ALGS
        RecvBufferSize = sizeof(TpmRespBuf);
        Status = Tpm2SubmitCommand (sizeof (Tpm2CapAlgs), Tpm2CapAlgs, &RecvBufferSize, TpmRespBuf);
        if (EFI_ERROR (Status))
        {
            break;
        }
        gBS->CopyMem (&u32TmpVal, &TpmRespBuf[0x0F], sizeof (u32TmpVal) );
        u32TmpVal = SwapBytes32 (u32TmpVal);
        Count = (UINTN)u32TmpVal;
        pByte = &TpmRespBuf[0x0F + 4];
        AlgPcrSupport = 0;
        for (Index = 0; Index < Count; ++Index)
        {
            gBS->CopyMem (&AlgID, pByte, sizeof (UINT16) );
            pByte += 2;
            AlgID = SwapBytes16 (AlgID);
            gBS->CopyMem (&u32TmpVal, pByte, sizeof (u32TmpVal) );
            pByte += 4;
            AlgProperties = SwapBytes32 (u32TmpVal);

//            DEBUG ((DEBUG_INFO, "AlgID [%04x], AlgProperties [%08x]\n", AlgID, AlgProperties));
            if (0x04 != AlgProperties)
            {
                continue;
            }

            if (TPM_ALG_SHA1 == AlgID)
            {
                AlgPcrSupport |= 0x01;
            }
            else if (TPM_ALG_SHA256 == AlgID)
            {
                AlgPcrSupport |= 0x02;
            }
            else if (TPM_ALG_SHA384 == AlgID)
            {
                AlgPcrSupport |= 0x04;
            }
            else if (TPM_ALG_SHA512 == AlgID)
            {
                AlgPcrSupport |= 0x08;
            }
            else if (TPM_ALG_SM3_256 == AlgID)
            {
                AlgPcrSupport |= 0x10;
            }
        }

        *SupportHashAlg = AlgPcrSupport;
    } while (FALSE);

    return Status;
}

EFI_STATUS Tpm2GetCapPCRs (
    UINT32  *pSupportedPcrBitMap,
    UINT32  *pActivePcrBitMap
)
{
    TPMS_CAPABILITY_DATA        TpmCap;
    TPMI_YES_NO                 MoreData;
    EFI_STATUS                  Status;
    TPMS_PCR_SELECTION          *PcrSelect;
    UINTN                       unIdx;
    UINT32                      SupportedPcrBitMap=0;
    UINT16                      u16HashAlg;

    UINT32                      ActivePcrBitMap = 0;
    UINT32                      u32PcrSelectCount = 0;

    do
    {
        SupportedPcrBitMap  = 0;
        ActivePcrBitMap     = 0;

        Status  = Tpm2GetCapability (
                        TPM_CAP_PCRS,
                        0,
                        MAX_PCR_PROPERTIES,
                        &MoreData,
                        &TpmCap);

        if(EFI_ERROR(Status))
        {
            DEBUG(( -1, "[%d]: Err. Tpm2GetCapability(TPM_CAP_PCRS)\n", __LINE__));
            break;
        }

        u32PcrSelectCount = SwapBytes32(TpmCap.data.assignedPCR.count);
        for( unIdx=0; unIdx<u32PcrSelectCount ; ++unIdx )
        {
            PcrSelect = &TpmCap.data.assignedPCR.pcrSelections[unIdx];
            u16HashAlg = SwapBytes16(PcrSelect->hash);
            switch(u16HashAlg)
            {
                case TPM_ALG_SHA1:
                    if( PcrSelect->pcrSelect[0] & 0xFF ) // Check the PCR0~7
                    {
                        ActivePcrBitMap |= 1;
                    }
                    break;
                case TPM_ALG_SHA256:
                    if( PcrSelect->pcrSelect[0] & 0xFF )
                    {
                        ActivePcrBitMap |= 2;
                    }
                    break;
                case TPM_ALG_SHA384:
                    if( PcrSelect->pcrSelect[0] & 0xFF )
                    {
                        ActivePcrBitMap |= 4;
                    }
                    break;
                case TPM_ALG_SHA512:
                    if( PcrSelect->pcrSelect[0] & 0xFF )
                    {
                        ActivePcrBitMap |= 8;
                    }
                    break;
                case TPM_ALG_SM3_256:
                    if( PcrSelect->pcrSelect[0] & 0xFF )
                    {
                        ActivePcrBitMap |= 0x10;
                    }
                    break;
              default:
                  DEBUG(( -1, "[%d]: Error for parsing \n", __LINE__));
                  Status = EFI_DEVICE_ERROR;
                  break;
            }
        }
    } while( FALSE );

    Status = Tpm2GetSupportPcrBank (&SupportedPcrBitMap);
    if( !EFI_ERROR(Status) )
    {
        DEBUG(( -1," SupportedPcrBitMap = %x \n", SupportedPcrBitMap));
        DEBUG(( -1," ActivePcrBitMap = %x \n", ActivePcrBitMap));

        *pSupportedPcrBitMap = SupportedPcrBitMap;
        *pActivePcrBitMap = ActivePcrBitMap;
    }

  return Status;
}
