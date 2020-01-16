#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include "sha.h"
#include "ShellDmpLog2.h"

//
// Create By HPBird
//

static EFI_TREE_PROTOCOL            *mTreeProtocol = NULL;
static EFI_TCG_PROTOCOL             *mTcgEfiProtocol = NULL;

CHAR16      u16StrBuf[StrBufLen];
UINT32      u32Tpm2ErrCode = 0;

EFI_STATUS
EFIAPI
TreeTpm2SubmitCommand (
  IN UINT32            InputParameterBlockSize,
  IN UINT8             *InputParameterBlock,
  IN OUT UINT32        *OutputParameterBlockSize,
  IN UINT8             *OutputParameterBlock
  )
{
  EFI_STATUS                Status;
  TPM2_RESPONSE_HEADER      *Header;

//    DEBUG(( DEBUG_INFO, "TPM Command Buffer:" ));
//    PrintBuf( InputParameterBlockSize, InputParameterBlock );
  
  //
  // Assume when TrEE Protocol is ready, RequestUseTpm already done.
  //
  Status = mTreeProtocol->SubmitCommand (
                            mTreeProtocol,
                            InputParameterBlockSize,
                            InputParameterBlock,
                            *OutputParameterBlockSize,
                            OutputParameterBlock
                            );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Header = (TPM2_RESPONSE_HEADER *)OutputParameterBlock;
  *OutputParameterBlockSize = SwapBytes32 (Header->paramSize);

  u32Tpm2ErrCode = SwapBytes32 (Header->responseCode);

//    DEBUG(( DEBUG_INFO, "TPM Response Buffer:" ));
//    PrintBuf( *OutputParameterBlockSize, OutputParameterBlock );
  
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
Tpm2SubmitCommand (
  IN UINT32            InputParameterBlockSize,
  IN UINT8             *InputParameterBlock,
  IN OUT UINT32        *OutputParameterBlockSize,
  IN UINT8             *OutputParameterBlock
  )
{
	EFI_STATUS		Status = EFI_SUCCESS;
	
	if( NULL == mTreeProtocol  )
	{
		if (mTreeProtocol == NULL )
		{
			Status = gBS->LocateProtocol (&gEfiTrEEProtocolGuid, NULL, (VOID **) &mTreeProtocol);
			if (EFI_ERROR (Status)) {
			  //
			  // TrEE protocol is not installed. So, TPM2 is not present.
			  //
//			  DEBUG ((DEBUG_INFO, "EfiTrEEProtocol - TrEE - %r\n", Status));
			}
		}
	}

    if( mTreeProtocol )
    {
        return TreeTpm2SubmitCommand(
                InputParameterBlockSize,
                InputParameterBlock,
                OutputParameterBlockSize,
                OutputParameterBlock );
    }

    return EFI_DEVICE_ERROR;
}

EFI_STATUS
EFIAPI
Tpm12SubmitCommand (
  IN UINT32            InputParameterBlockSize,
  IN UINT8             *InputParameterBlock,
  IN OUT UINT32        *OutputParameterBlockSize,
  IN UINT8             *OutputParameterBlock
  )
{
    EFI_STATUS      Status = EFI_SUCCESS;

    if( NULL == mTcgEfiProtocol  )
    {
        if (mTreeProtocol == NULL )
        {
            Status = gBS->LocateProtocol (&gEfiTcgProtocolGuid, NULL, (VOID **) &mTcgEfiProtocol);
            if (EFI_ERROR (Status)) {
              //
              // TrEE protocol is not installed. So, TPM2 is not present.
              //
//              DEBUG ((DEBUG_INFO, "TcgEfiProtocol - Tpm12 - %r\n", Status));
            }
        }
    }

    if( mTcgEfiProtocol )
    {
        return mTcgEfiProtocol->PassThroughToTpm(
                                                    mTcgEfiProtocol,
                                                    InputParameterBlockSize,
                                                    InputParameterBlock,
                                                    *OutputParameterBlockSize,
                                                    OutputParameterBlock
        );
    }

    return EFI_DEVICE_ERROR;
}

VOID* Memset (VOID* Dest, int _SetByte, UINTN _size)
{
    SetMem (Dest, _size, (UINT8)_SetByte);
    return Dest;
}

VOID PrintBuf(
    UINTN   unBufSize,
    UINT8*  _buf
)
{
    UINTN   unIdx;
    for( unIdx = 0; unIdx<unBufSize; ++unIdx )
    {
        if( unIdx % 0x10 == 0 )
            DEBUG(( DEBUG_INFO, "\n" ));

        DEBUG(( DEBUG_INFO, " %02x", _buf[unIdx] ));
    }

    DEBUG(( DEBUG_INFO, "\n" ));
}

UINT32 GetStrLen(CONST CHAR8* _str)
{
	UINT32	u32StrCount;
	for(u32StrCount = 0; _str[u32StrCount] != '\0'; ++u32StrCount) {};
	return u32StrCount;
}

UINTN WStrlen(CHAR16 *string)
{
    UINTN length=0;
    while(*string++) length++;
    return length;
}

VOID sha1_vector(UINTN num_elem, CONST UINT8 *addr[], CONST UINTN *len, UINT8 *mac)
{
    SHA_CTX     ctx;
    UINTN       i;

    SHA1_Init(&ctx);
    for (i = 0; i < num_elem; i++)
        SHA1_Update(&ctx, addr[i], len[i]);
    SHA1_Final(mac, &ctx);

    SetMem (&ctx, sizeof(ctx), 0);
}

VOID sha256_vector(
    UINTN           num_elem,
    CONST UINT8     *addr[],
    CONST UINTN     *len,
    UINT8           *mac)
{
    SHA256_CTX  ctx;
    UINTN       i;

    SHA256_Init(&ctx);
    for (i = 0; i < num_elem; i++)
        SHA256_Update(&ctx, addr[i], len[i]);
    SHA256_Final(mac, &ctx);

    SetMem (&ctx, sizeof(ctx), 0);
}

VOID sha384_vector(
    UINTN           num_elem,
    CONST UINT8     *addr[],
    CONST UINTN     *len,
    UINT8           *mac)
{
    SHA512_CTX  ctx;
    UINTN       i;

    SHA384_Init(&ctx);
    for (i = 0; i < num_elem; i++)
        SHA384_Update(&ctx, addr[i], len[i]);
    SHA384_Final(mac, &ctx);

    SetMem (&ctx, sizeof(ctx), 0);
}

VOID sha512_vector(
    UINTN           num_elem,
    CONST UINT8     *addr[],
    CONST UINTN     *len,
    UINT8           *mac)
{
    SHA512_CTX  ctx;
    UINTN       i;

    SHA512_Init(&ctx);
    for (i = 0; i < num_elem; i++)
        SHA512_Update(&ctx, addr[i], len[i]);
    SHA512_Final(mac, &ctx);

    SetMem (&ctx, sizeof(ctx), 0);
}

VOID sm3_vector(
    UINTN           num_elem,
    CONST UINT8     *addr[],
    CONST UINTN     *len,
    UINT8           *mac)
{
    sm3_ctx_t       ctx;
    UINTN           i;

    sm3_init (&ctx);
    for (i = 0; i < num_elem; i++)
        sm3_update(&ctx, addr[i], len[i]);
    sm3_final (&ctx, mac);

    SetMem (&ctx, sizeof(ctx), 0);
}
