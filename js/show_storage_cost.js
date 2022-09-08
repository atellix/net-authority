const { Buffer } = require('buffer')
const { DateTime } = require("luxon")
const { v4: uuidv4, parse: uuidparse } = require('uuid')
const { PublicKey, SystemProgram, SYSVAR_RENT_PUBKEY } = require('@solana/web3.js')
const { TOKEN_PROGRAM_ID } = require('@solana/spl-token')
const { promisify } = require('util')
const exec = promisify(require('child_process').exec)
const fs = require('fs').promises
const base32 = require("base32.js")
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

    const rootData = await programAddress([netAuthorityPK.toBuffer()], netAuthorityPK)
    const mchAdmin = importSecretKey(netKeys['merchant-admin-1-secret'])
    const merchantPK = new PublicKey(netData.merchant1)

    const infoData = await programAddress([merchantPK.toBuffer(), Buffer.from('merchant-details', 'utf8')], netAuthorityPK)
    const infoBytes = 373
    const infoRent = await provider.connection.getMinimumBalanceForRentExemption(infoBytes)
    console.log('Merchant Details')
    console.log((new PublicKey(infoData.pubkey)).toString(), infoBytes, infoRent)

    console.log('Create Merchant Details')
    let res = await netAuthority.rpc.storeMerchantDetails(
        rootData.nonce,
        false, // create
        false,
        new anchor.BN(infoBytes),
        new anchor.BN(infoRent),
        "SavvyCo, Inc.",
        "https://savvyco.com/",
        "",
        {
            accounts: {
                feePayer: provider.wallet.publicKey,
                rootData: new PublicKey(rootData.pubkey),
                authData: new PublicKey(netData.netAuthorityRBAC),
                merchantAdmin: mchAdmin.publicKey,
                merchantInfo: new PublicKey(infoData.pubkey),
                merchantKey: merchantPK,
                systemProgram: SystemProgram.programId
            },
            signers: [mchAdmin],
        }
    )
    console.log(res)
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
