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
const { associatedTokenAddress, programAddress, exportSecretKey, jsonFileRead, jsonFileWrite } = require('../../js/atellix-common')

const provider = anchor.Provider.env()
//const provider = anchor.Provider.local()
anchor.setProvider(provider)
const netAuthority = anchor.workspace.NetAuthority
const netAuthorityPK = netAuthority.programId

async function main() {
    var jsres = await exec('solana program show --output json ' + netAuthorityPK.toString())
    var res = JSON.parse(jsres.stdout)
    const programData = res.programdataAddress

    const infoData = await programAddress([netAuthorityPK.toBuffer(), Buffer.from('metadata', 'utf8')], netAuthorityPK)
    const infoBytes = 584
    const infoRent = await provider.connection.getMinimumBalanceForRentExemption(infoBytes)
    console.log('Program Metadata')
    console.log((new PublicKey(infoData.pubkey)).toString(), infoBytes, infoRent)

    console.log('Create Metadata')
    console.log(await netAuthority.rpc.storeMetadata(
        "Network Authority",
        "Atellix Network",
        "https://atellix.network/",
        "https://github.com/atellix/net-authority",
        "",
        {
            accounts: {
                program: netAuthorityPK,
                programAdmin: provider.wallet.publicKey,
                programData: new PublicKey(programData),
                programInfo: new PublicKey(infoData.pubkey),
                systemProgram: SystemProgram.programId
            }
        }
    ))
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
