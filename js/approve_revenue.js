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
const provider = anchor.Provider.env()
//const provider = anchor.Provider.local()
anchor.setProvider(provider)
const netAuthority = anchor.workspace.NetAuthority
const netAuthorityPK = netAuthority.programId

const tokenMint = new PublicKey('HZE3aet4kKEnBdKsTAWcc9Axv6F7p9Yu4rcNJcuxddZr')
//console.log('Net Authority Program')
//console.log(netAuthorityPK.toString())

const SPL_ASSOCIATED_TOKEN = new PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL')
async function associatedTokenAddress(walletAddress, tokenMintAddress) {
    const addr = await PublicKey.findProgramAddress(
        [walletAddress.toBuffer(), TOKEN_PROGRAM_ID.toBuffer(), tokenMintAddress.toBuffer()],
        SPL_ASSOCIATED_TOKEN
    )
    const res = { 'pubkey': await addr[0].toString(), 'nonce': addr[1] }
    return res
}

async function programAddress(inputs, programPK = netAuthorityPK) {
    const addr = await PublicKey.findProgramAddress(inputs, programPK)
    const res = { 'pubkey': await addr[0].toString(), 'nonce': addr[1] }
    return res
}

function exportSecretKey(keyPair) {
    var enc = new base32.Encoder({ type: "crockford", lc: true })
    return enc.write(keyPair.secretKey).finalize()
}

async function main() {
    var ndjs
    try {
        ndjs = await fs.readFile('net.json')
    } catch (error) {
        console.error('File Error: ', error)
    }
    const tokenAgentPK = new PublicKey('yPiRxxJKpHoZhoDZZtSVbGBJMXT8e9FyG5cCmWxzgY7')
    const netData = JSON.parse(ndjs.toString())
    const rootData = await programAddress([netAuthorityPK.toBuffer()])
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
