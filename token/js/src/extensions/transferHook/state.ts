import { blob, greedy, seq, struct, u32, u8 } from '@solana/buffer-layout';
import type { Mint } from '../../state/mint.js';
import { ExtensionType, getExtensionData } from '../extensionType.js';
import type { AccountInfo, AccountMeta } from '@solana/web3.js';
import { PublicKey } from '@solana/web3.js';
import { bool, publicKey } from '@solana/buffer-layout-utils';
import type { Account } from '../../state/account.js';
import { TokenTransferHookAccountNotFound } from '../../errors.js';
import { unpackSeeds } from './seeds.js';

/** TransferHook as stored by the program */
export interface TransferHook {
    /** The transfer hook update authrority */
    authority: PublicKey;
    /** The transfer hook program account */
    programId: PublicKey;
}

/** Buffer layout for de/serializing a transfer hook extension */
export const TransferHookLayout = struct<TransferHook>([publicKey('authority'), publicKey('programId')]);

export const TRANSFER_HOOK_SIZE = TransferHookLayout.span;

export function getTransferHook(mint: Mint): TransferHook | null {
    const extensionData = getExtensionData(ExtensionType.TransferHook, mint.tlvData);
    if (extensionData !== null) {
        return TransferHookLayout.decode(extensionData);
    } else {
        return null;
    }
}

/** TransferHookAccount as stored by the program */
export interface TransferHookAccount {
    /**
     * Whether or not this account is currently tranferring tokens
     * True during the transfer hook cpi, otherwise false
     */
    transferring: boolean;
}

/** Buffer layout for de/serializing a transfer hook account extension */
export const TransferHookAccountLayout = struct<TransferHookAccount>([bool('transferring')]);

export const TRANSFER_HOOK_ACCOUNT_SIZE = TransferHookAccountLayout.span;

export function getTransferHookAccount(account: Account): TransferHookAccount | null {
    const extensionData = getExtensionData(ExtensionType.TransferHookAccount, account.tlvData);
    if (extensionData !== null) {
        return TransferHookAccountLayout.decode(extensionData);
    } else {
        return null;
    }
}

export function getExtraAccountMetaAccount(programId: PublicKey, mint: PublicKey): PublicKey {
    const seeds = [Buffer.from('extra-account-metas'), mint.toBuffer()];
    return PublicKey.findProgramAddressSync(seeds, programId)[0];
}

/** ExtraAccountMeta as stored by the transfer hook program */
export interface ExtraAccountMeta {
    discriminator: number;
    addressConfig: Uint8Array;
    isSigner: boolean;
    isWritable: boolean;
}

/** Buffer layout for de/serializing an ExtraAccountMeta */
export const ExtraAccountMetaLayout = struct<ExtraAccountMeta>([
    u8('discriminator'),
    blob(32, 'addressConfig'),
    bool('isSigner'),
    bool('isWritable'),
]);

export interface ExtraAccountMetaList {
    count: number;
    extraAccounts: ExtraAccountMeta[];
}

/** Buffer layout for de/serializing a list of ExtraAccountMeta prefixed by a u32 length */
export const ExtraAccountMetaListLayout = struct<ExtraAccountMetaList>([
    u32('count'),
    seq<ExtraAccountMeta>(ExtraAccountMetaLayout, greedy(ExtraAccountMetaLayout.span), 'extraAccounts'),
]);

/** Unpack an extra account metas account and parse the data into a list of ExtraAccountMetas */
export function getExtraAccountMetas(account: AccountInfo<Buffer>): ExtraAccountMeta[] {
    return ExtraAccountMetaListLayout.decode(account.data).extraAccounts;
}

/** Take an ExtraAccountMeta and construct that into an acutal AccountMeta */
export function resolveExtraAccountMeta(
    extraMeta: ExtraAccountMeta,
    previousMetas: AccountMeta[],
    instructionData: Buffer,
    transferHookProgramId: PublicKey
): AccountMeta {
    if (extraMeta.discriminator === 0) {
        return {
            pubkey: new PublicKey(extraMeta.addressConfig),
            isSigner: extraMeta.isSigner,
            isWritable: extraMeta.isWritable,
        };
    }

    let programId = PublicKey.default;

    if (extraMeta.discriminator === 1) {
        programId = transferHookProgramId;
    } else {
        const accountIndex = extraMeta.discriminator - (1 << 7);
        if (previousMetas.length <= accountIndex) {
            throw new TokenTransferHookAccountNotFound();
        }
        programId = previousMetas[accountIndex].pubkey;
    }

    const seeds = unpackSeeds(extraMeta.addressConfig, previousMetas, instructionData);
    const pubkey = PublicKey.findProgramAddressSync(seeds, programId)[0];

    return { pubkey, isSigner: extraMeta.isSigner, isWritable: extraMeta.isWritable };
}
