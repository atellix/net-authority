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
    const aquaDexIDL = await jsonFileRead('../../aqua-dex/target/idl/aqua_dex.json')
    const aquaDexPK = new PublicKey(aquaDexIDL.metadata.address)
    const aquaDex = new anchor.Program(aquaDexIDL, aquaDexPK, provider)
    //console.log(aquaDex)

    const netData = await jsonFileRead('../../data/net.json')
    const rootData = await programAddress([netAuthorityPK.toBuffer()], netAuthorityPK)
    const tknAdmin = importSecretKey(netData['merchantAdmin1_secret'])

    const group = new PublicKey('DGzjPXnFFNw18FXSuMJVfwBThxBU2ohc2gAwsf2Z6FgA')

    const market = anchor.web3.Keypair.generate()
    const marketAgent = await programAddress([market.publicKey.toBuffer()], aquaDexPK)
    const marketAgentPK = new PublicKey(marketAgent.pubkey)
    const marketAuth = await programAddress([marketAgentPK.toBuffer(), group.toBuffer()], netAuthorityPK)
    const marketAuthPK = new PublicKey(marketAuth.pubkey)

    console.log("Market: " + market.publicKey.toString())
    console.log("Market Auth: " + marketAuthPK.toString())

    const tx = new anchor.web3.Transaction()
    tx.add(anchor.web3.SystemProgram.createAccount({
        fromPubkey: provider.wallet.publicKey,
        newAccountPubkey: market.publicKey,
        space: aquaDex.account.market.size,
        lamports: await provider.connection.getMinimumBalanceForRentExemption(aquaDex.account.market.size),
        programId: aquaDexPK,
    }))
    tx.add(netAuthority.instruction.approveToken(
        rootData.nonce,
        true, // true = group, false = mint
        {
            accounts: {
                rootData: new PublicKey(rootData.pubkey),
                authData: new PublicKey(netData.netAuthorityRBAC),
                tokenAdmin: tknAdmin.publicKey,
                owner: marketAgentPK,
                context: group,
                approval: marketAuthPK,
                feePayer: provider.wallet.publicKey,
                systemProgram: SystemProgram.programId,
            },
        }
    ))
    console.log(await provider.send(tx, [tknAdmin, market]))
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
