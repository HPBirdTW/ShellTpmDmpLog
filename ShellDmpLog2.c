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
#include <Guid\EventGroup.h>
#include "ShellDmpLog2.h"

EFI_GUID                        gEfiTrEEProtocolGuid    = EFI_TREE_PROTOCOL_GUID;

EFI_GUID                        gEfiTcgProtocolGuid     = EFI_TCG_PROTOCOL_GUID;

//extern EFI_FILE_PROTOCOL        *gWriteFile;

UINTN               g_EventStartAddr = 0;
UINTN               g_EventEndAddr = 0;

VOID ShowChkTCGEvent(IN EFI_EVENT Event, IN VOID *Context)
{
    EFI_STATUS                      Status;
    EFI_TREE_PROTOCOL               *TreeProtocol;
    EFI_TCG_PROTOCOL                *tcgEfiProtocol;
    EFI_STATUS Tpm20Sha1DmpLog (VOID);
    EFI_STATUS CalcSMLTpm20PCR_Tcg_1_2 (VOID);
    EFI_STATUS Tpm12Sha1DmpLog (VOID);
    EFI_STATUS CalcSMLTpm12PCR (VOID);
    EFI_STATUS Tpm20ProtocolCapability (VOID);
    EFI_STATUS ShowSMLTpm20HashPCR (VOID);

    // Checking the TPM 2.0?
    do
    {
        // Check the TPM20 TrEEProtocol.
        Status = gBS->LocateProtocol (&gEfiTrEEProtocolGuid, NULL, (VOID **) &TreeProtocol);
        if (EFI_ERROR (Status))
        {
            SPrintf( L"(Tpm20)Locate[gEfiTrEEProtocolGuid]: -%r [0x%08x]\n\r", Status, Status);
            break;;
        }

        Status = Tpm20ProtocolCapability();
        if (EFI_ERROR (Status))
        {
            break;
        }

        Status = Tpm20Sha1DmpLog();
        if (EFI_ERROR (Status))
        {
            // Keep process the TCG_2 Event Log
//            break;
        }
        else
        {
            Status = CalcSMLTpm20PCR_Tcg_1_2();
            if (EFI_ERROR (Status))
            {
                // Keep process the TCG_2 Event Log
//                break;
            }
        }

        Status = ShowSMLTpm20HashPCR ();
        if (EFI_ERROR (Status))
        {
            break;
        }
    } while (FALSE);

    // Check TPM 1.2 Device?
    do
    {
        // Check the TPM12
        Status = gBS->LocateProtocol (&gEfiTcgProtocolGuid, NULL, &tcgEfiProtocol);
        if ( EFI_ERROR( Status ))
        {
            SPrintf (L"(Tpm12)Locate[gEfiTcgProtocolGuid]: -%r [0x%08x]\n\r", Status, Status);
            break;
        }

        Status = Tpm12Sha1DmpLog();
        if (EFI_ERROR (Status))
        {
            break;
        }

        Status = CalcSMLTpm12PCR ();
        if (EFI_ERROR (Status))
        {
            break;
        }
    } while (FALSE);

    return;

}

EFI_STATUS ShellDmpLog2EntryPoint(
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
)
{
    EFI_STATUS 		        Status = EFI_SUCCESS;
    static EFI_EVENT        Event = NULL;
    static EFI_GUID         ReadyToBoot = EFI_EVENT_GROUP_READY_TO_BOOT;

#if BUILD_SHELL_TOOLS
    ShowChkTCGEvent( NULL, NULL );
#else
    Status = gBS->CreateEventEx(
            EVT_NOTIFY_SIGNAL, TPL_CALLBACK,
            &ShowChkTCGEvent,
            NULL, &ReadyToBoot,
            &Event
        );
#endif

    return EFI_SUCCESS;
}
