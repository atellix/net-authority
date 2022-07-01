const { Buffer } = require('buffer')
const { DateTime } = require('luxon')
const { v4: uuidv4, parse: uuidparse } = require('uuid')
const { PublicKey, Keypair, SystemProgram, SYSVAR_RENT_PUBKEY } = require('@solana/web3.js')
const { TOKEN_PROGRAM_ID } = require('@solana/spl-token')
const { promisify } = require('util')
const exec = promisify(require('child_process').exec)
const fs = require('fs').promises
const base32 = require('base32.js')
const anchor = require('@project-serum/anchor')
const { associatedTokenAddress, programAddress, importSecretKey, exportSecretKey, jsonFileRead, jsonFileWrite } = require('../../js/atellix-common')

const provider = anchor.Provider.env()
//const provider = anchor.Provider.local()
anchor.setProvider(provider)
const netAuthority = anchor.workspace.NetAuthority
const netAuthorityPK = netAuthority.programId

async function main() {
    const netKeys = await jsonFileRead('../../data/export/network_keys.json')
    const netData = await jsonFileRead('../../data/net.json')
    const swpData = await jsonFileRead('../../data/swap.json')

    const rootData = await programAddress([netAuthorityPK.toBuffer()], netAuthorityPK)
    const mchAdmin = importSecretKey(netKeys['merchant-admin-1-secret'])

    const revenueProgram = new PublicKey(netData.tokenAgentProgram)
    const swapProgram = new PublicKey(swpData.swapContractProgram)
    const revenueAdmin = await programAddress([revenueProgram.toBuffer()], revenueProgram)
    const swapAdmin = await programAddress([swapProgram.toBuffer()], swapProgram)

    const tokenMint = new PublicKey(netData['tokenMintUSDV'])

    console.log('Create Merchant')

    const mch = anchor.web3.Keypair.generate()
    const mchApproval = anchor.web3.Keypair.generate()
    var resData = {}
    resData['merchant'] = mch.publicKey.toString()
    resData['merchant_secret'] = exportSecretKey(mch)
    resData['merchantApproval'] = mchApproval.publicKey.toString()
    resData['merchantApproval_secret'] = exportSecretKey(mchApproval)

    console.log('Create Merchant Token')
    var res = await exec('spl-token create-account ' + netData['tokenMintUSDV'] + ' --owner ' + resData['merchant'] + ' --output json')
    console.log(res.stdout)

    console.log('Approve Merchant')
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
                    merchantApproval: new PublicKey(resData.merchantApproval),
                    merchantKey: new PublicKey(resData.merchant),
                    tokenMint: tokenMint,
                    feesAccount: new PublicKey(netData.fees1_token),
                    revenueAdmin: new PublicKey(revenueAdmin.pubkey),
                    swapAdmin: new PublicKey(swapAdmin.pubkey),
                    systemProgram: SystemProgram.programId,
                },
            }
        )
    )
    console.log(await provider.send(tx, [mchAdmin, mchApproval]))
    console.log(resData)
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
