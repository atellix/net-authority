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

    console.log('Close Merchant 1')
    await netAuthority.rpc.closeMerchantApproval(
        rootData.nonce,
        {
            accounts: {
                rootData: new PublicKey(rootData.pubkey),
                authData: new PublicKey(netData.netAuthorityRBAC),
                feeReceiver: provider.wallet.publicKey,
                merchantAdmin: mchAdmin.publicKey,
                merchantApproval: new PublicKey('FSmwWnCZQ9STM3Bm78Xrwx6bHvhwbTxX33GdX9McKKNA'),
            },
            signers: [mchAdmin],
        }
    )
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
