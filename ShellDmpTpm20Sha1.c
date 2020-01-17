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

EFI_STATUS TCG_PCR_EVENT_PrintOneEvent(TCG_PCR_EVENT* pStart, TCG_PCR_EVENT** pNext);
EFI_STATUS GetNextSMLEvent(TCG_PCR_EVENT* pStart, TCG_PCR_EVENT** pNext);

struct
{
    UINT32  ManufactureId;
    CHAR16* str;
} CONST VenderID[] = {
        {   0x414d4400,     L"AMD(fTPM)" },
        {   0x41544d4c,     L"Atmel"     },
        {   0x4252434d,     L"Broadcom"  },
        {   0x49424d00,     L"IBM"       },
        {   0x49465800,     L"Infineon"  },
        {   0x494e5443,     L"Intel(fTPM)"   },
        {   0x4c454e00,     L"Lenovo"    },
        {   0x4e534d20,     L"National Semi" },
        {   0x4e545a00,     L"Nationz"   },
        {   0x4e544300,     L"Nuvoton Technology"    },
        {   0x51434f4d,     L"Qualcomm"  },
        {   0x534d5343,     L"SMSC"      },
        {   0x53544d20,     L"STMicroelectronics"    },
        {   0x534d534e,     L"Samsung"   },
        {   0x534e5300,     L"Sinosun"   },
        {   0x54584e00,     L"Texas Instruments" },
        {   0x57454300,     L"Winbond"   },
        {   0x524f4343,     L"Fuzhou Rockchip"   }
};

EFI_STATUS Tpm20ProtocolCapability (VOID)
{
    EFI_TREE_PROTOCOL                   *TreeProtocol;
    UINT8                               u8Buf[0x100];
    TREE_BOOT_SERVICE_CAPABILITY        *pCap = NULL;
    EFI_STATUS                          Status = EFI_SUCCESS;
    UINTN                               unIdx;

    pCap = (TREE_BOOT_SERVICE_CAPABILITY*)&u8Buf[0];

//    DEBUG((DEBUG_INFO,"Enter Tpm20ProtocolCapability(...)\n"));

    do
    {
        SetMem (u8Buf, sizeof(u8Buf), 0);

        Status = gBS->LocateProtocol (&gEfiTrEEProtocolGuid, NULL, (VOID **) &TreeProtocol);
        if (EFI_ERROR (Status)) {
            PString(L"Can not Locate[gEfiTrEEProtocolGuid]. Failed.\n\r");;
            break;
        }

        pCap->Size = 0xFF;
        Status = TreeProtocol->GetCapability( TreeProtocol, pCap );
        if (EFI_ERROR (Status))
        {
            SPrintf (L"Failed Get TreeProtocol->GetCapability(...) -%r [%x]\n\r", Status, Status);
            break;
        }

        SPrintf (L"\n\rGet TreeProtocol->GetCapability(...).", Status);
        SPrintBufMixChar( (UINTN)pCap->Size, (UINT8*)pCap );
        SPrintf (L"Dump the common structure\n\r");
        SPrintf (L"  Size                   [%x]\n\r", (UINTN)pCap->Size);
        SPrintf (L"  StructureVersion.Major [%x]\n\r", (UINTN)pCap->StructureVersion.Major);
        SPrintf (L"  StructureVersion.Minor [%x]\n\r", (UINTN)pCap->StructureVersion.Minor);
        SPrintf (L"  ProtocolVersion.Major  [%x]\n\r", (UINTN)pCap->ProtocolVersion.Major);
        SPrintf (L"  ProtocolVersion.Minor  [%x]\n\r", (UINTN)pCap->ProtocolVersion.Minor);
        SPrintf (L"  HashAlgorithmBitmap    [0x%08x]", (UINTN)pCap->HashAlgorithmBitmap);
        if (pCap->HashAlgorithmBitmap == 0)
        {
            SPrintf (L"\n\r");
        }
        else
        {
            SPrintf (L": ");
            if (pCap->HashAlgorithmBitmap & EFI_TCG2_BOOT_HASH_ALG_SHA1)
                SPrintf (L"|SHA1");
            if (pCap->HashAlgorithmBitmap & EFI_TCG2_BOOT_HASH_ALG_SHA256)
                SPrintf (L"|SHA256");
            if (pCap->HashAlgorithmBitmap & EFI_TCG2_BOOT_HASH_ALG_SHA384)
                SPrintf (L"|SHA384");
            if (pCap->HashAlgorithmBitmap & EFI_TCG2_BOOT_HASH_ALG_SHA512)
                SPrintf (L"|SHA512");
            if (pCap->HashAlgorithmBitmap & EFI_TCG2_BOOT_HASH_ALG_SM3_256)
                SPrintf (L"|SM3_256");
            SPrintf (L"|\n\r");
        }
        SPrintf (L"  SupportedEventLogs     [0x%08x]", (UINTN)pCap->SupportedEventLogs);
        if (pCap->SupportedEventLogs == 0)
        {
            SPrintf (L"\n\r");
        }
        else
        {
            SPrintf (L": ");
            if (pCap->SupportedEventLogs & EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2)
                SPrintf (L"|TCG_1_2(SHA1)");
            if (pCap->SupportedEventLogs & EFI_TCG2_EVENT_LOG_FORMAT_TCG_2)
                SPrintf (L"|TCG_2");
            SPrintf (L"|\n\r");
        }
        SPrintf (L"  TrEEPresentFlag        [%x]\n\r", (UINTN)pCap->TrEEPresentFlag);
        SPrintf (L"  MaxCommandSize         [%x]\n\r", (UINTN)pCap->MaxCommandSize);
        SPrintf (L"  MaxResponseSize        [%x]\n\r", (UINTN)pCap->MaxResponseSize);
        for( unIdx = 0; unIdx < sizeof(VenderID)/sizeof(VenderID[0]); ++unIdx)
        {
            if( VenderID[unIdx].ManufactureId == pCap->ManufacturerID )
            {
                SPrintf(L"  ManufacturerID         [0x%08x]: %s\n\r", VenderID[unIdx].ManufactureId, VenderID[unIdx].str);
                break;
            }
        }
        if (unIdx == sizeof(VenderID)/sizeof(VenderID[0]))
        {
            SPrintf( L"  ManufacturerID         [%x]\n\r", (UINTN)pCap->ManufacturerID);
        }
    } while (FALSE);

    return Status;
}

EFI_STATUS Tpm20Sha1DmpLog (VOID)
{
    EFI_STATUS                      Status = EFI_SUCCESS;
    TCG_PCR_EVENT*                  pNext = NULL;
    UINTN                           unEventCount = 0;
    EFI_TREE_PROTOCOL               *TreeProtocol;
    EFI_PHYSICAL_ADDRESS            EventStartAddr = 0;
    EFI_PHYSICAL_ADDRESS            EventEndAddr = 0;
    BOOLEAN                         bLogTruncated = FALSE;
    UINT8                           u8Buf[0x100];
    TREE_BOOT_SERVICE_CAPABILITY    *pCap = NULL;

//    DEBUG((DEBUG_INFO,"Enter TCG_1_2(...)\n"));

    do
    {
        Status = gBS->LocateProtocol (&gEfiTrEEProtocolGuid, NULL, (VOID **) &TreeProtocol);
        if (EFI_ERROR (Status)) {
            PString(L"Can not Locate[gEfiTrEEProtocolGuid]. Failed.\n\r");;
            break;
        }

        SetMem( u8Buf, sizeof(u8Buf), 0);
        pCap = (TREE_BOOT_SERVICE_CAPABILITY*)&u8Buf[0];
        pCap->Size = 0xFF;

        Status = TreeProtocol->GetCapability( TreeProtocol, pCap );
        if (EFI_ERROR (Status))
        {
            SPrintf (L"Failed Get TreeProtocol->GetCapability(...) -%r [%x]\n\r", Status, Status);
            break;
        }

        if (0 == (pCap->SupportedEventLogs & EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2))
        {
            Status = EFI_NOT_FOUND;
            break;
        }

        Status = TreeProtocol->GetEventLog (TreeProtocol,
                                            EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2,
                                            &EventStartAddr,
                                            &EventEndAddr,
                                            &bLogTruncated );
        if( EFI_ERROR(Status) )
        {
            SPrintf (L"Failed Get TreeProtocol->GetEventLog(...) -%r [%x]\n\r", Status, Status);
            break;
        }

        SPrintf (L"Get TreeProtocol->GetEventLog (...)\n\r");
        SPrintf (L"    EventLogLocation     [%x]\n\r", (UINTN)EventStartAddr);
        SPrintf (L"    EventLogLastEntry    [%x]\n\r", (UINTN)EventEndAddr );
        SPrintf (L"    EventLogTruncated    [%x]\n\r", bLogTruncated == TRUE ? 0x01 : 0x00);

        g_EventStartAddr = (UINTN)EventStartAddr;
        g_EventEndAddr = (UINTN)EventEndAddr;

        SPrintf(L"\n\rDump Tpm20 TCG_1_2 Event(...)\n\r");

        pNext = (TCG_PCR_EVENT*)EventStartAddr;
        do {
            if( 0 == (UINTN)EventEndAddr )
            {
                SPrintf( L"Get Empty Event log\n\r");
                break;
            }
            ++unEventCount;
            if( (UINTN)pNext >= (UINTN)EventEndAddr )
            {
                TCG_PCR_EVENT_PrintOneEvent( pNext, &pNext);
                SPrintf( L"End of the Event Log, Total Count [%d]\n\r", unEventCount);
                break;
            }
        } while( EFI_SUCCESS == TCG_PCR_EVENT_PrintOneEvent( pNext, &pNext));

    } while (FALSE);

    return Status;
}

EFI_STATUS ChkSha1StartupLocalityEvent( TCG_PCR_EVENT* pEvent, UINTN *Locality )
{
    EFI_STATUS                          Status;
    CONST UINT8                         StartLocality[] = "StartupLocality";

    do
    {
        Status = EFI_SUCCESS;
        if (pEvent->PCRIndex != 0x00)
        {
            Status = EFI_NOT_FOUND;
            break;
        }
        if (pEvent->EventType != 0x03)
        {
            Status = EFI_NOT_FOUND;
            break;
        }
        if (pEvent->EventSize != sizeof(TCG_EFI_STARTUP_LOCALITY_EVENT))
        {
            Status = EFI_NOT_FOUND;
            break;
        }
        if (0 != CompareMem (((TCG_EFI_STARTUP_LOCALITY_EVENT*)pEvent->Event)->Signature, StartLocality, sizeof(StartLocality)) )
        {
            Status = EFI_NOT_FOUND;
            break;
        }

        *Locality = (UINTN)((TCG_EFI_STARTUP_LOCALITY_EVENT*)pEvent->Event)->StartupLocality;
    } while( 0 );

    return Status;
}

EFI_STATUS CalcSMLTpm20PCR_Tcg_1_2 (VOID)
{
    EFI_PHYSICAL_ADDRESS    EventStartAddr = 0;
    EFI_PHYSICAL_ADDRESS    EventEndAddr = 0;
    TCG_PCR_EVENT*          pNext = NULL;
    EFI_STATUS              Status;
    UINT8                   EvaDigest[2][SHA1_DIGEST_SIZE];
    UINT8                   HashVal[SHA1_DIGEST_SIZE];
    UINT8                   pcrValue[SHA1_DIGEST_SIZE];
    UINT8                   EmptyDigest[SHA1_DIGEST_SIZE];
    UINT32                  unPCRIdx = 0;
    UINTN                   unInitStartupLocality = 0;

    BOOLEAN                 bLogTruncated = FALSE;
    EFI_TREE_PROTOCOL       *TreeProtocol;

//    DEBUG((DEBUG_INFO,"Enter CalcSMLTpm20PCR_Tcg_1_2(...)"));

    do
    {
        Status = gBS->LocateProtocol (&gEfiTrEEProtocolGuid, NULL, (VOID **) &TreeProtocol);
        if (EFI_ERROR (Status)) {
            PString(L"Can not Locate[gEfiTrEEProtocolGuid]. Failed.\n\r");
            break;
        }

        Status = TreeProtocol->GetEventLog (TreeProtocol,
                                            TREE_EVENT_LOG_FORMAT_TCG_1_2,
                                            &EventStartAddr,
                                            &EventEndAddr,
                                            &bLogTruncated );
        if (EFI_ERROR (Status))
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

        g_EventStartAddr = (UINTN)EventStartAddr;
        g_EventEndAddr = (UINTN)EventEndAddr;

        SPrintf (L"\n\rStart Tpm20 TCG_1_2 Calc Event(...)");

        SetMem (EmptyDigest, sizeof(EmptyDigest), 0);

__RepCheck:
        pNext = (TCG_PCR_EVENT*)EventStartAddr;
        SetMem (EvaDigest, sizeof(EvaDigest), 0);
        SetMem (HashVal, sizeof(HashVal), 0);

        do {
            Status = ChkSha1StartupLocalityEvent (pNext, &unInitStartupLocality);
            if( !EFI_ERROR(Status) && 0 == unPCRIdx )
            {
                EvaDigest[0][SHA1_DIGEST_SIZE-1] = (UINT8)unInitStartupLocality;
            }
            if( pNext->PCRIndex == unPCRIdx && pNext->EventType != 0x03 )
            {
                CopyMem (&EvaDigest[1], &(pNext->Digest), SHA1_DIGEST_SIZE);
                Sha1HashData ((UINT8*)(UINTN)&EvaDigest, sizeof(EvaDigest), &HashVal[0]);
                CopyMem (&EvaDigest[0], &HashVal, SHA1_DIGEST_SIZE);
            }
            Status = GetNextSMLEvent (pNext, &pNext);
        } while (EFI_SUCCESS == Status );

        SPrintf (L"\n\rEVA_VALUE[%02x]", (UINTN)unPCRIdx);
        SPrintBuf (SHA1_DIGEST_SIZE, &HashVal[0]);

        SetMem (&pcrValue[0], sizeof(pcrValue), 0);
        Status = Tpm2Sha1PCRRead (unPCRIdx, &pcrValue[0]);
        if (!EFI_ERROR(Status))
        {
            SPrintf( L"PCR_VALUE[%02x]", (UINTN)unPCRIdx );

            SPrintBuf( SHA1_DIGEST_SIZE, &pcrValue[0] );
        }
        else
        {
            SPrintf( L"\n\r Failed Tpm2Sha1PCRRead (...) - %r [0x%08x]\n\r", Status, (UINTN)Status );
        }

        if( ++unPCRIdx <= 7 )
            goto __RepCheck;
    } while (FALSE);
    SPrintf(L"\n\rEnd Tpm20 TCG_1_2 Calc Event(...)\n\r");

    return Status;
}

EFI_STATUS GetNextSMLEvent(TCG_PCR_EVENT* pStart, TCG_PCR_EVENT** pNext)
{
    UINT8*          _pStart = (UINT8*)pStart;
    UINTN           unIdx = 0;

    *pNext = (TCG_PCR_EVENT*)(_pStart + STRUCT_FIELD_OFFSET( TCG_PCR_EVENT, Event ) + pStart->EventSize );

    if( !(*pNext)->EventType && !(*pNext)->EventSize )
        return EFI_NOT_FOUND;

    if( (UINTN)(*pNext) > g_EventEndAddr )
        return EFI_NOT_FOUND;

    return EFI_SUCCESS;
}
