#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include "ShellDmpLog2.h"

//
// Create By HPBird
//

EFI_STATUS TCG_PCR_EVENT_PrintOneEvent(TCG_PCR_EVENT* pStart, TCG_PCR_EVENT** pNext);

EFI_STATUS Tpm12Sha1DmpLog (VOID)
{
    EFI_STATUS                          Status = EFI_SUCCESS;
    EFI_PHYSICAL_ADDRESS                EventStartAddr = 0;
    EFI_PHYSICAL_ADDRESS                EventEndAddr = 0;
    TCG_PCR_EVENT*                      pNext = NULL;
    TCG_EFI_BOOT_SERVICE_CAPABILITY     Cap;
    EFI_TCG_PROTOCOL                    *TcgProtocol;

//    DEBUG((-1,"Enter Tpm12Sha1DmpLog(...)\n"));

    do
    {
        Status = gBS->LocateProtocol (&gEfiTcgProtocolGuid, NULL, (VOID **) &TcgProtocol);
        if (EFI_ERROR (Status))
        {
            SPrintf (L"Can't locate [gEfiTcgProtocolGuid]. Failed Return - %r [0x%08x]\n\r", Status, Status);
            break;;
        }

        Status = TcgProtocol->StatusCheck( TcgProtocol, &Cap, NULL, &EventStartAddr, &EventEndAddr );
        if (EFI_ERROR (Status))
        {
            SPrintf ( L"Failed Get TcgProtocol->StatusCheck -%r [0x%08x]\n\r", Status, Status);
            break;
        }
        if( Cap.TPMDeactivatedFlag )
        {
            SPrintf (L"The TPM12 is Deactivate, Can not get the Event Log\n\r");
            break;
        }

        SPrintf (L"    EventLogLocation [0x%08x]\n\r", (UINTN)EventStartAddr);
        SPrintf (L"    EventLogLastEntry[0x%08x]\n\r", (UINTN)EventEndAddr);

        if (0 == EventStartAddr || 0 == EventEndAddr)
        {
            Status = EFI_INVALID_PARAMETER;
            SPrintf (L"Invalid parameter of (EventLogLocation | EventLogLastEntry)\n\r");
            break;
        }

        g_EventStartAddr = (UINTN)EventStartAddr;
        g_EventEndAddr = (UINTN)EventEndAddr;

        SPrintf(L"Tpm12 DmpLog Event (...)\n\r");

        pNext = (TCG_PCR_EVENT*)EventStartAddr;
        do {
            if( 0 == (UINTN)EventEndAddr )
            {
                SPrintf( L"Get Empty Event log\n\r");
                break;
            }
            if( (UINTN)pNext >= (UINTN)EventEndAddr )
            {
                TCG_PCR_EVENT_PrintOneEvent( pNext, &pNext);
                SPrintf( L"End of the Event Log\n\r");
                break;
            }
        } while( EFI_SUCCESS == TCG_PCR_EVENT_PrintOneEvent( pNext, &pNext));

    } while (FALSE);

    return Status;
}

EFI_STATUS GetTpm12NextSMLEvent(TCG_PCR_EVENT* pStart, TCG_PCR_EVENT** pNext);

EFI_STATUS CalcSMLTpm12PCR (VOID)
{
    EFI_PHYSICAL_ADDRESS    EventStartAddr = 0;
    EFI_PHYSICAL_ADDRESS    EventEndAddr = 0;
    TCG_PCR_EVENT*          pNext = NULL;
    EFI_STATUS              Status;
    UINT8                   EvaDigest[2][SHA1_DIGEST_SIZE];
    UINT8                   HashVal[SHA1_DIGEST_SIZE];
    UINT8                   pcrValue[SHA1_DIGEST_SIZE];
    UINT32                  unPCRIdx = 0;

    EFI_STATUS Tpm12PCRRead( UINT32, UINT8* );

    TCG_EFI_BOOT_SERVICE_CAPABILITY     Cap;
    EFI_TCG_PROTOCOL                    *TcgProtocol;

//    DEBUG((-1,"Enter CalcSMLTpm12PCR(...)"));

    do
    {
        Status = gBS->LocateProtocol (&gEfiTcgProtocolGuid, NULL, (VOID **) &TcgProtocol);
        if (EFI_ERROR (Status))
        {
            SPrintf (L"Can't locate [gEfiTcgProtocolGuid]. Failed Return - %r [0x%08x]\n\r", Status, Status);
            break;;
        }

        Status = TcgProtocol->StatusCheck( TcgProtocol, &Cap, NULL, &EventStartAddr, &EventEndAddr );
        if (EFI_ERROR (Status))
        {
            SPrintf ( L"Failed Get TcgProtocol->StatusCheck -%r [0x%08x]\n\r", Status, Status);
            break;
        }
        if( Cap.TPMDeactivatedFlag )
        {
            SPrintf (L"The TPM12 is Deactivate, Can not get the Event Log\n\r");
            break;
        }

        if (0 == EventStartAddr || 0 == EventEndAddr)
        {
            Status = EFI_INVALID_PARAMETER;
            SPrintf (L"Invalid parameter of (EventLogLocation | EventLogLastEntry)\n\r");
            break;
        }

        g_EventStartAddr = (UINTN)EventStartAddr;
        g_EventEndAddr = (UINTN)EventEndAddr;

        SPrintf(L"Start Tpm12 SML Calc Event(...)\n\r");
__RepCheck:
        pNext = (TCG_PCR_EVENT*)EventStartAddr;
        SetMem (EvaDigest, sizeof(EvaDigest), 0);

        do {
            if (pNext->PCRIndex == unPCRIdx && pNext->EventType != 0x03)
            {
                CopyMem (&EvaDigest[1], &(pNext->Digest), SHA1_DIGEST_SIZE);
                Sha1HashData ((UINT8*)(UINTN)&EvaDigest, sizeof(EvaDigest), &HashVal[0]);
                CopyMem (&EvaDigest[0], &HashVal, SHA1_DIGEST_SIZE);
            }
            Status = GetTpm12NextSMLEvent (pNext, &pNext);
        } while (EFI_SUCCESS == Status);

        SPrintf( L"\n\rEVA_VALUE[%02x]", (UINTN)unPCRIdx );
        SPrintBuf (SHA1_DIGEST_SIZE, &HashVal[0]);

        Tpm12PCRRead( unPCRIdx, &pcrValue[0]);
        SPrintf( L"PCR_VALUE[%02x]", (UINTN)unPCRIdx );
        SPrintBuf (SHA1_DIGEST_SIZE, &pcrValue[0]);

        if( ++unPCRIdx <= 7 )
            goto __RepCheck;

        SPrintf(L"\n\rEnd Tpm12 SML Calc Event(...)\n\r");
    } while (FALSE);

    return Status;
}

EFI_STATUS GetTpm12NextSMLEvent(TCG_PCR_EVENT* pStart, TCG_PCR_EVENT** pNext)
{
    UINT8*          _pStart = (UINT8*)pStart;
    UINTN           unIdx = 0;

    *pNext = (TCG_PCR_EVENT*)(_pStart + STRUCT_FIELD_OFFSET( TCG_PCR_EVENT, Event ) + pStart->EventSize );

    if( !(*pNext)->EventType && !(*pNext)->EventSize )
        return -1;

    if( (UINTN)(*pNext) > g_EventEndAddr )
        return -1;

    return EFI_SUCCESS;
}

#pragma pack (push, 1)
typedef struct _Tpm12_PcrRead_Cmd {
  UINT16                tag;
  UINT32                paramSize;
  UINT32                ordinal;
  UINT32                pcrIndex;
} Tpm12_PcrRead_Cmd;

typedef struct _Tpm12_PcrRead_Ret {
  UINT16                tag;
  UINT32                paramSize;
  UINT32                returnCode;
  UINT8                 outDigest[20];
} Tpm12_PcrRead_Ret;
#pragma pack (pop)

EFI_STATUS Tpm12PCRRead(
    IN  UINT32      PCRIndex,
    OUT UINT8       *Digest )
{
    Tpm12_PcrRead_Cmd   Cmd;
    Tpm12_PcrRead_Ret   Ret;
    EFI_STATUS          Status;
    UINT32              u32RetSize;

    Cmd.tag         = SwapBytes16( TPM_TAG_RQU_COMMAND );
    Cmd.paramSize   = SwapBytes32( sizeof (Cmd) );

    Cmd.ordinal     = SwapBytes32( TPM_ORD_PcrRead );
    Cmd.pcrIndex    = SwapBytes32( PCRIndex );

    u32RetSize = sizeof(Ret);
    Status = Tpm12SubmitCommand(
                                sizeof(Cmd),
                                (UINT8*)&Cmd,
                                &u32RetSize,
                                (UINT8*)&Ret
                                );
    if( !EFI_ERROR(Status) )
    {
        if( Ret.returnCode )
        {
            Status = EFI_NOT_READY;
        }
        else
        {
            CopyMem (Digest, Ret.outDigest, sizeof(Ret.outDigest));
        }
    }

    return Status;
}

