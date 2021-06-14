import * as schema from './schema.js';
import solanaWeb3 from '@solana/web3.js';

/**
 * Sample code to demonstrate how to use the JS bindings
 * Also contains several useful helper functions
 */

export class StakePool {
  /**
   * Wrapper class for a stake pool.
   * Each stake pool has a stake pool account and a validator list account.
   */
  stakePool: decodedStakePool;
  validatorList: decodedValidatorList;
}

export interface decodedStakePool {
  pubkey: solanaWeb3.PublicKey;
  account: solanaWeb3.AccountInfo<schema.StakePoolAccount>;
}

export interface decodedValidatorList {
  pubkey: solanaWeb3.PublicKey;
  account: solanaWeb3.AccountInfo<schema.ValidatorListAccount>;
}

export async function getStakePoolAccount(
  connection: solanaWeb3.Connection,
  stakePoolPubKey: solanaWeb3.PublicKey,
): Promise<decodedStakePool> {
  /**
   * Retrieves and deserializes a StakePool account using a web3js connection and the stake pool address.
   * @param connection: An active web3js connection.
   * @param stakePoolPubKey: The public key (address) of the stake pool account.
   */
  try {
    const account = await connection.getAccountInfo(stakePoolPubKey);

    return {
      pubkey: stakePoolPubKey,
      account: {
        data: schema.StakePoolAccount.decode(account.data),
        executable: account.executable,
        lamports: account.lamports,
        owner: account.owner,
      },
    };
  } catch (error) {
    console.log(error);
  }
}

export async function getValidatorListAccount(
  connection: solanaWeb3.Connection,
  validatorListPubKey: solanaWeb3.PublicKey,
): Promise<decodedValidatorList> {
  /**
   * Retrieves and deserializes a ValidatorList account using a web3js connection and the validator list address.
   * @param connection: An active web3js connection.
   * @param validatorListPubKey: The public key (address) of the validator list account.
   */
  try {
    const account = await connection.getAccountInfo(validatorListPubKey);

    return {
      pubkey: validatorListPubKey,
      account: {
        data: schema.ValidatorListAccount.decode(account.data),
        executable: account.executable,
        lamports: account.lamports,
        owner: account.owner,
      },
    };
  } catch (error) {
    console.log(error);
  }
}

export async function getStakePoolAccounts(
  connection: solanaWeb3.Connection,
  stakePoolProgramAddress: solanaWeb3.PublicKey,
): Promise<(decodedStakePool | decodedValidatorList)[]> {
  /**
   * Retrieves all StakePool and ValidatorList accounts that are running a particular StakePool program.
   * @param connection: An active web3js connection.
   * @param stakePoolProgramAddress: The public key (address) of the StakePool program.
   */
  try {
    let response = await connection.getProgramAccounts(stakePoolProgramAddress);

    const stakePoolAccounts = response.map(a => {
      let decodedData;

      if (a.account.data.readUInt8() === 1) {
        decodedData = schema.StakePoolAccount.decode(a.account.data);
      } else if (a.account.data.readUInt8() === 2) {
        decodedData = schema.ValidatorListAccount.decode(a.account.data);
      } else {
        throw `StakePoolAccount Enum is ${a.account.data.readUInt8()}, expected 1 or 2!`;
      }

      return {
        pubkey: a.pubkey,
        account: {
          data: decodedData,
          executable: a.account.executable,
          lamports: a.account.lamports,
          owner: a.account.owner,
        },
      };
    });

    return stakePoolAccounts;
  } catch (error) {
    console.log('I have an error');
    console.log(error);
  }
}

export function prettyPrintPubKey(pubKey: schema.PublicKey): string {
  /**
   * Helper function to pretty print a schema.PublicKey
   * Pretty prints a PublicKey in base58 format */

  return new solanaWeb3.PublicKey(
    new solanaWeb3.PublicKey(pubKey.value.toBuffer()).toBytes().reverse(),
  ).toString();
}

export function prettyPrintAccount(
  account: decodedValidatorList | decodedStakePool,
): void {
  /**
   * Helper function to pretty print a decoded account
   */

  console.log('Address:', account.pubkey.toString());
  const sp = account.account.data;
  for (const val in sp) {
    if (sp[val] instanceof schema.PublicKey) {
      console.log(val, prettyPrintPubKey(sp[val]));
    } else {
      console.log(val, sp[val]);
    }
  }
  console.log('Executable?:', account.account.executable);
  console.log('Lamports:', account.account.lamports);
  console.log('Owner PubKey:', account.account.owner.toString());
}
