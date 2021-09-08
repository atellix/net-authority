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

const tokenMint = new PublicKey('9YJSAZehJRU3vLMfor7mXF9B4KCQZ6LAzP1tV7ek8kb9')
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

async function programAddress(inputs) {
    const addr = await PublicKey.findProgramAddress(inputs, netAuthorityPK)
    const res = { 'pubkey': await addr[0].toString(), 'nonce': addr[1] }
    return res
}

function exportSecretKey(keyPair) {
    var enc = new base32.Encoder({ type: "crockford", lc: true })
    return enc.write(keyPair.secretKey).finalize()
}

async function main() {
    var netData = {}
    netData['tokenMintUSDV'] = tokenMint.toString()
    netData['netAuthorityProgram'] = netAuthorityPK.toString()

    var jsres = await exec('solana program show --output json ' + netAuthorityPK.toString())
    var res = JSON.parse(jsres.stdout)
    const programData = res.programdataAddress
    netData['netAuthorityProgramData'] = programData

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
    netData['netAuthorityRBAC'] = authData.publicKey.toString()

    const mgrAdmin = anchor.web3.Keypair.generate()
    netData['managerAdmin1'] = mgrAdmin.publicKey.toString()
    netData['managerAdmin1_secret'] = exportSecretKey(mgrAdmin)

    const mchAdmin = anchor.web3.Keypair.generate()
    netData['merchantAdmin1'] = mchAdmin.publicKey.toString()
    netData['merchantAdmin1_secret'] = exportSecretKey(mchAdmin)

    const fees1 = anchor.web3.Keypair.generate()
    const fees1token = await associatedTokenAddress(fees1.publicKey, tokenMint)
    netData['fees1'] = fees1.publicKey.toString()
    netData['fees1_secret'] = exportSecretKey(fees1)
    netData['fees1_token'] = fees1token.pubkey

    const mgr1 = anchor.web3.Keypair.generate()
    const mgrApproval1 = anchor.web3.Keypair.generate()
    netData['manager1'] = mgr1.publicKey.toString()
    netData['manager1_secret'] = exportSecretKey(mgr1)
    netData['managerApproval1'] = mgrApproval1.publicKey.toString()
    netData['managerApproval1_secret'] = exportSecretKey(mgrApproval1)

    const mch1 = anchor.web3.Keypair.generate()
    const mchApproval1 = anchor.web3.Keypair.generate()
    netData['merchant1'] = mch1.publicKey.toString()
    netData['merchant1_secret'] = exportSecretKey(mch1),
    netData['merchantApproval1'] = mchApproval1.publicKey.toString()
    netData['merchantApproval1_secret'] = exportSecretKey(mchApproval1)

    /* var sk = exportSecretKey(mch1)
    var dec = new base32.Decoder({ type: "crockford" })
    var dk = dec.write(sk).finalize()
    var rk = anchor.web3.Keypair.fromSecretKey(new Uint8Array(dk))
    console.log(mch1.publicKey.toString())
    console.log(sk)
    console.log(rk.publicKey.toString()) */

    //process.exit(0)

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

    console.log('Grant 1: Manager Admin 1')
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

    console.log('Grant 2: Merchant Admin 1')
    await netAuthority.rpc.grant(
        rootData.nonce,
        2,
        {
            accounts: {
                program: netAuthorityPK,
                programAdmin: provider.wallet.publicKey,
                programData: new PublicKey(programData),
                rootData: new PublicKey(rootData.pubkey),
                authData: authData.publicKey,
                rbacUser: mchAdmin.publicKey,
            },
        }
    )
    console.log('Grant 2 Done')

    /* console.log('Grant 3: Swap Deposit 1')
    await netAuthority.rpc.grant(
        rootData.nonce,
        4,
        {
            accounts: {
                program: netAuthorityPK,
                programAdmin: provider.wallet.publicKey,
                programData: new PublicKey(programData),
                rootData: new PublicKey(rootData.pubkey),
                authData: authData.publicKey,
                rbacUser: swapDeposit1.publicKey,
            },
        }
    )
    console.log('Grant 3 Done')

    console.log('Grant 4: Swap Withdraw 1')
    await netAuthority.rpc.grant(
        rootData.nonce,
        5,
        {
            accounts: {
                program: netAuthorityPK,
                programAdmin: provider.wallet.publicKey,
                programData: new PublicKey(programData),
                rootData: new PublicKey(rootData.pubkey),
                authData: authData.publicKey,
                rbacUser: swapWithdraw1.publicKey,
            },
        }
    )
    console.log('Grant 4 Done') */

    if (true) {
        const tx = new anchor.web3.Transaction()
        tx.add(
            anchor.web3.SystemProgram.createAccount({
                fromPubkey: provider.wallet.publicKey,
                newAccountPubkey: mgrApproval1.publicKey,
                space: netAuthority.account.managerApproval.size,
                lamports: await provider.connection.getMinimumBalanceForRentExemption(netAuthority.account.managerApproval.size),
                programId: netAuthorityPK,
            })
        )
        await provider.send(tx, [mgrApproval1])

        const tx2 = new anchor.web3.Transaction()
        tx2.add(
            anchor.web3.SystemProgram.createAccount({
                fromPubkey: provider.wallet.publicKey,
                newAccountPubkey: mchApproval1.publicKey,
                space: netAuthority.account.merchantApproval.size,
                lamports: await provider.connection.getMinimumBalanceForRentExemption(netAuthority.account.merchantApproval.size),
                programId: netAuthorityPK,
            })
        )
        await provider.send(tx2, [mchApproval1])
    }
 
    console.log('Approve Manager 1')
    await netAuthority.rpc.approveManager(
        rootData.nonce,
        {
            accounts: {
                rootData: new PublicKey(rootData.pubkey),
                authData: authData.publicKey,
                managerAdmin: mgrAdmin.publicKey,
                managerApproval: mgrApproval1.publicKey,
                managerKey: mgr1.publicKey,
            },
            signers: [mgrAdmin],
        }
    )

    console.log('Approve Merchant 1')
    await netAuthority.rpc.approveMerchant(
        rootData.nonce,
        100,
        {
            accounts: {
                rootData: new PublicKey(rootData.pubkey),
                authData: authData.publicKey,
                merchantAdmin: mchAdmin.publicKey,
                merchantApproval: mchApproval1.publicKey,
                merchantKey: mch1.publicKey,
                tokenMint: tokenMint,
                feesAccount: new PublicKey(fees1token.pubkey),
            },
            signers: [mchAdmin],
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

    try {
        await fs.writeFile('net.json', JSON.stringify(netData, null, 4))
    } catch (error) {
        console.log("File Error: " + error)
    }
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
