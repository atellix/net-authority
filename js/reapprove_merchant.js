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
const { associatedTokenAddress, programAddress, exportSecretKey, importSecretKey, jsonFileRead, jsonFileWrite } = require('../../js/atellix-common')

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

    const mchApproval1 = anchor.web3.Keypair.generate()
    console.log('New Merchant Approval 1:')
    console.log(mchApproval1.publicKey.toString())
    console.log(exportSecretKey(mchApproval1))

    const tokenMint = new PublicKey(netData['tokenMintUSDV'])

    console.log('Create Merchant 1 Approval Account')
    const tx3 = new anchor.web3.Transaction()
    tx3.add(
        anchor.web3.SystemProgram.createAccount({
            fromPubkey: provider.wallet.publicKey,
            newAccountPubkey: mchApproval1.publicKey,
            space: netAuthority.account.merchantApproval.size,
            lamports: await provider.connection.getMinimumBalanceForRentExemption(netAuthority.account.merchantApproval.size),
            programId: netAuthorityPK,
        })
    )
    await provider.send(tx3, [mchApproval1])
 
    console.log('Approve Merchant 1')
    await netAuthority.rpc.approveMerchant(
        rootData.nonce,
        100,
        {
            accounts: {
                rootData: new PublicKey(rootData.pubkey),
                authData: new PublicKey(netData.netAuthorityRBAC),
                merchantAdmin: mchAdmin.publicKey,
                merchantApproval: mchApproval1.publicKey,
                merchantKey: new PublicKey(netData.merchant1),
                tokenMint: tokenMint,
                feesAccount: new PublicKey(netData.fees1_token),
            },
            signers: [mchAdmin],
        }
    )
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
