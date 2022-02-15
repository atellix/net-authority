const { Buffer } = require('buffer')
const { DateTime } = require("luxon")
const { v4: uuidv4, parse: uuidparse } = require('uuid')
const { PublicKey, Keypair, SystemProgram, SYSVAR_RENT_PUBKEY } = require('@solana/web3.js')
const { TOKEN_PROGRAM_ID } = require('@solana/spl-token')
const { promisify } = require('util')
const exec = promisify(require('child_process').exec)
const fs = require('fs').promises
const base32 = require("base32.js")
const anchor = require('@project-serum/anchor')
const { associatedTokenAddress, programAddress, importSecretKey, jsonFileRead, jsonFileWrite } = require('../../js/atellix-common')

const provider = anchor.Provider.env()
//const provider = anchor.Provider.local()
anchor.setProvider(provider)
const netAuthority = anchor.workspace.NetAuthority
const netAuthorityPK = netAuthority.programId

async function main() {
    const netKeys = await jsonFileRead('../../data/export/network_keys.json')
    const netData = await jsonFileRead('../../data/net.json')

    const rootData = await programAddress([netAuthorityPK.toBuffer()], netAuthorityPK)
    const mchAdmin = importSecretKey(netKeys['merchant-admin-1-secret'])

    const tokenMint = new PublicKey(netData['tokenMintUSDV'])
    // TODO: Fund associated token account for all relevant mints

    const mrchApproval1 = importSecretKey(netData['merchantApproval1_secret'])

    console.log('Approve Merchant 1')
    const tx = new anchor.web3.Transaction()
    tx.add(
        anchor.web3.SystemProgram.transfer({
            fromPubkey: provider.wallet.publicKey,
            toPubkey: mchAdmin.publicKey,
            lamports: await provider.connection.getMinimumBalanceForRentExemption(netAuthority.account.merchantApproval.size),
        })
    )
    tx.add(
        netAuthority.instruction.approveMerchant(
            rootData.nonce,
            100,
            {
                accounts: {
                    rootData: new PublicKey(rootData.pubkey),
                    authData: new PublicKey(netData.netAuthorityRBAC),
                    merchantAdmin: mchAdmin.publicKey,
                    merchantApproval: new PublicKey(netData.merchantApproval1),
                    merchantKey: new PublicKey(netData.merchant1),
                    tokenMint: tokenMint,
                    feesAccount: new PublicKey(netData.fees1_token),
                    systemProgram: SystemProgram.programId,
                },
            }
        )
    )
    await provider.send(tx, [mchAdmin, mrchApproval1])
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
