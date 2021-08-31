const { Buffer } = require('buffer')
const { DateTime } = require("luxon")
const { v4: uuidv4, parse: uuidparse } = require('uuid')
const { PublicKey, SystemProgram, SYSVAR_RENT_PUBKEY } = require('@solana/web3.js')
const { TOKEN_PROGRAM_ID } = require('@solana/spl-token')
const { promisify } = require('util')
const exec = promisify(require('child_process').exec)

const anchor = require('@project-serum/anchor')
//const provider = anchor.Provider.env()
const provider = anchor.Provider.local()
anchor.setProvider(provider)
const netAuthority = anchor.workspace.NetAuthority
const netAuthorityPK = netAuthority.programId
console.log('Net Authority Program')
console.log(netAuthorityPK.toString())

async function programAddress(inputs) {
    const addr = await PublicKey.findProgramAddress(inputs, netAuthorityPK)
    const res = { 'pubkey': await addr[0].toString(), 'nonce': addr[1] }
    return res
}

async function main() {
    var jsres = await exec('solana program show --output json ' + netAuthorityPK.toString())
    var res = JSON.parse(jsres.stdout)
    const programData = res.programdataAddress
    
    const rootData = await programAddress([netAuthorityPK.toBuffer()])
    const rootBytes = netAuthority.account.rootData.size
    const rootRent = await provider.connection.getMinimumBalanceForRentExemption(rootBytes)
    console.log('Root Data')
    console.log((new PublicKey(rootData.pubkey)).toString(), rootBytes, rootRent)

    const authData = anchor.web3.Keypair.generate()
    const authBytes = 130 + (16384 * 6)
    const authRent = await provider.connection.getMinimumBalanceForRentExemption(authBytes)
    console.log('Auth Data')
    console.log(authData.publicKey.toString(), authBytes, authRent)

    if (true) {
        const tx = new anchor.web3.Transaction()
        tx.add(
            anchor.web3.SystemProgram.createAccount({
                fromPubkey: provider.wallet.publicKey,
                newAccountPubkey: authData.publicKey,
                space: authBytes,
                lamports: authRent,
                programId: netAuthorityPK,
            })
        )
        await provider.send(tx, [authData])
    }

    console.log('Initialize')
    await netAuthority.rpc.initialize(
        new anchor.BN(rootBytes),
        new anchor.BN(rootRent),
        {
            accounts: {
                program: netAuthorityPK,
                programAdmin: provider.wallet.publicKey,
                programData: new PublicKey(programData),
                rootData: new PublicKey(rootData.pubkey),
                authData: authData.publicKey
            },
            remainingAccounts: [
                { pubkey: provider.wallet.publicKey, isWritable: true, isSigner: true },
                { pubkey: new PublicKey(rootData.pubkey), isWritable: true, isSigner: false },
                { pubkey: SystemProgram.programId, isWritable: false, isSigner: false }
            ]
        }
    )

    console.log('Grant 1')
    const mgrAdmin = anchor.web3.Keypair.generate()
    const mgrApproval = anchor.web3.Keypair.generate()
    const subscrMgr1 = anchor.web3.Keypair.generate()
    //const merchAdmin = anchor.web3.Keypair.generate()
    await netAuthority.rpc.grant(
        rootData.nonce,
        1,
        {
            accounts: {
                program: netAuthorityPK,
                programAdmin: provider.wallet.publicKey,
                programData: new PublicKey(programData),
                rootData: new PublicKey(rootData.pubkey),
                authData: authData.publicKey,
                rbacUser: mgrAdmin.publicKey,
            },
        }
    )
    console.log('Grant 1 Done')

    if (true) {
        const tx = new anchor.web3.Transaction()
        tx.add(
            anchor.web3.SystemProgram.createAccount({
                fromPubkey: provider.wallet.publicKey,
                newAccountPubkey: mgrApproval.publicKey,
                space: netAuthority.account.managerApproval.size,
                lamports: await provider.connection.getMinimumBalanceForRentExemption(netAuthority.account.managerApproval.size),
                programId: netAuthorityPK,
            })
        )
        await provider.send(tx, [mgrApproval])
    }
 
    console.log('Approve Manager 1')
    await netAuthority.rpc.approveManager(
        rootData.nonce,
        {
            accounts: {
                rootData: new PublicKey(rootData.pubkey),
                authData: authData.publicKey,
                managerAdmin: mgrAdmin.publicKey,
                managerApproval: mgrApproval.publicKey,
                managerKey: subscrMgr1.publicKey,
            },
            signers: [mgrAdmin],
        }
    )

/*    console.log('Revoke 1')
    await netAuthority.rpc.revoke(
        rootData.nonce,
        1,
        {
            accounts: {
                program: netAuthorityPK,
                programAdmin: provider.wallet.publicKey,
                programData: new PublicKey(programData),
                rootData: new PublicKey(rootData.pubkey),
                authData: authData.publicKey,
                rbacUser: mgrAdmin.publicKey,
            },
        }
    ) */

    // TODO: Test NetworkAdmin
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
