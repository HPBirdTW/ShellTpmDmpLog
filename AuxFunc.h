

EFI_STATUS PString(CHAR16* _str);
EFI_STATUS SPrintf( CHAR16* _str, ... );
EFI_STATUS StrConOutf( CHAR16* _str, ... );
VOID PrintBuf(
    UINTN   unBufSize,
    UINT8*  _buf
);
VOID SPrintBuf(
    UINTN   unBufSize,
    UINT8*  _buf
);

VOID SPrintBufMixChar(
    UINTN   unBufSize,
    UINT8*  _buf
);

UINT32 GetStrLen(CONST CHAR8* _str);

UINTN WStrlen(CHAR16 *string);

#define         StrBufLen 0x400
extern CHAR16   u16StrBuf[StrBufLen];


VOID sha1_vector(UINTN num_elem, CONST UINT8 *addr[], CONST UINTN *len,
        UINT8 *mac);

VOID sha256_vector(UINTN num_elem, CONST UINT8 *addr[], CONST UINTN *len,
        UINT8 *mac);

VOID sha384_vector(UINTN num_elem, CONST UINT8 *addr[], CONST UINTN *len,
        UINT8 *mac);

VOID sha512_vector(UINTN num_elem, CONST UINT8 *addr[], CONST UINTN *len,
        UINT8 *mac);

VOID sm3_vector(UINTN num_elem, CONST UINT8 *addr[], CONST UINTN *len,
        UINT8 *mac);

EFI_STATUS
EFIAPI
Tpm2SubmitCommand (
  IN UINT32            InputParameterBlockSize,
  IN UINT8             *InputParameterBlock,
  IN OUT UINT32        *OutputParameterBlockSize,
  IN UINT8             *OutputParameterBlock
  );

EFI_STATUS
EFIAPI
Tpm12SubmitCommand (
  IN UINT32            InputParameterBlockSize,
  IN UINT8             *InputParameterBlock,
  IN OUT UINT32        *OutputParameterBlockSize,
  IN UINT8             *OutputParameterBlock
);
