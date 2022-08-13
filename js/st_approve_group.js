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
    const netData = await jsonFileRead('../../data/net.json')
    const rootData = await programAddress([netAuthorityPK.toBuffer()], netAuthorityPK)
    const tknAdmin = importSecretKey(netData['merchantAdmin1_secret'])

    const owner = new PublicKey('G9GUQuEKS6oJsZspUrAJ1aWFqp1SPq5tgCja4wpMueyX')
    const group = new PublicKey('91Q2u3RvAp64qB9H84gFnUmwkT1s4MZSXWxu7PMZ6Wre')

    const tokenApproval = await programAddress([owner.toBuffer(), group.toBuffer()], netAuthorityPK)
    console.log('Approve Owner 1: ' + tokenApproval.pubkey)
    const tx = new anchor.web3.Transaction()
    tx.add(
        netAuthority.instruction.approveTokenGroup(
            rootData.nonce,
            {
                accounts: {
                    rootData: new PublicKey(rootData.pubkey),
                    authData: new PublicKey(netData.netAuthorityRBAC),
                    tokenAdmin: tknAdmin.publicKey,
                    owner: owner,
                    group: group,
                    approval: new PublicKey(tokenApproval.pubkey),
                    feePayer: provider.wallet.publicKey,
                    systemProgram: SystemProgram.programId,
                },
            }
        )
    )
    console.log(await provider.send(tx, [tknAdmin]))
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
