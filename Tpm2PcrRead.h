/*
 * Copyright (C) 2019 HPBirdChen (hpbirdtw@gmail.com)
 * All rights reserved.
 * The License file locate on:
 * https://github.com/HPBirdTW/ShellTpmDmpLog/license.txt
 * */

EFI_STATUS Tpm2ShaAlgoIdPCRRead(
    IN UINT16           AlgorithmId,
    IN TPM_PCRINDEX     PCRIndex,
    OUT UINT8*          Digest );

EFI_STATUS Tpm2Sha1PCRRead(
    IN TPM_PCRINDEX     PCRIndex,
    OUT UINT8*          Digest );

EFI_STATUS Tpm2Sha256PCRRead(
    IN TPM_PCRINDEX     PCRIndex,
    OUT UINT8           *Digest );

EFI_STATUS Tpm2Sha384PCRRead(
    IN TPM_PCRINDEX PCRIndex,
    OUT UINT8       *Digest );

EFI_STATUS Tpm2Sha512PCRRead(
    IN TPM_PCRINDEX PCRIndex,
    OUT UINT8       *Digest );

EFI_STATUS Tpm2Sm3_256PCRRead(
    IN TPM_PCRINDEX     PCRIndex,
    OUT UINT8           *Digest );
