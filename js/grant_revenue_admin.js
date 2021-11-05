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
//console.log('Net Authority Program')
//console.log(netAuthorityPK.toString())

async function main() {
    const netData = await jsonFileRead('../../data/net.json')

    const tokenAgentPK = new PublicKey(netData.tokenAgentProgram)
    const rootData = await programAddress([netAuthorityPK.toBuffer()], netAuthorityPK)
    const agentRoot = await programAddress([tokenAgentPK.toBuffer()], tokenAgentPK)

    console.log('Grant: RevenueAdmin - ' + agentRoot.pubkey)
    await netAuthority.rpc.grant(
        rootData.nonce,
        3, // RevenueAdmin
        {
            accounts: {
                program: new PublicKey(netData.netAuthorityProgram),
                programAdmin: provider.wallet.publicKey,
                programData: new PublicKey(netData.netAuthorityProgramData),
                rootData: new PublicKey(rootData.pubkey),
                authData: new PublicKey(netData.netAuthorityRBAC),
                rbacUser: new PublicKey(agentRoot.pubkey),
            },
        }
    )
    console.log('Grant Done')
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
