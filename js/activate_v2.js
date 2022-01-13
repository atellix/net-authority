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
//console.log('Net Authority Program')
//console.log(netAuthorityPK.toString())

async function main() {
    const netKeys = await jsonFileRead('../../data/export/network_keys.json')

    let netData = {
        'tokenMintUSDV': netKeys['usdv-token-1-public'],
        'tokenMintUSDC': 'Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr', // Dummy Token: https://spl-token-faucet.com/
        // Mainnet:
        //'tokenMintUSDC': 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', // USD Coin
        //'tokenMintUSDT': 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB', // Tether
    }
    const tokenMint = new PublicKey(netData['tokenMintUSDV'])
    netData['netAuthorityProgram'] = netAuthorityPK.toString()

    var jsres = await exec('solana program show --output json ' + netAuthorityPK.toString())
    var res = JSON.parse(jsres.stdout)
    const programData = res.programdataAddress
    netData['netAuthorityProgramData'] = programData

    const rootData = await programAddress([netAuthorityPK.toBuffer()], netAuthorityPK)
    const rootBytes = netAuthority.account.rootData.size
    const rootRent = await provider.connection.getMinimumBalanceForRentExemption(rootBytes)
    console.log('Root Data')
    console.log((new PublicKey(rootData.pubkey)).toString(), rootBytes, rootRent)

    const authData = anchor.web3.Keypair.generate()
    const authBytes = 130 + (16384 * 2)
    const authRent = await provider.connection.getMinimumBalanceForRentExemption(authBytes)
    console.log('Auth Data')
    console.log(authData.publicKey.toString(), authBytes, authRent)
    netData['netAuthorityRBAC'] = authData.publicKey.toString()

    const netAdminPK = new PublicKey(netKeys['netauth-network-admin-1-public'])
    netData['networkAdmin1'] = netAdminPK.toString()

    const mgrAdmin = importSecretKey(netKeys['netauth-manager-admin-1-secret'])
    const mgrAdminPK = new PublicKey(netKeys['netauth-manager-admin-1-public'])
    netData['managerAdmin1'] = mgrAdminPK.toString()

    const mchAdminPK = new PublicKey(netKeys['merchant-admin-1-public'])
    netData['merchantAdmin1'] = mchAdminPK.toString()
    netData['merchantAdmin1_seret'] = netKeys['merchant-admin-1-secret']

    const fees1 = new PublicKey(netKeys['merchant-fees-1-public'])
    const fees1token = await associatedTokenAddress(fees1, tokenMint)
    netData['fees1'] = fees1.toString()
    netData['fees1_token'] = fees1token.pubkey

    const mgr1 = new PublicKey(netKeys['manager-1-public'])
    const mgrApproval1 = anchor.web3.Keypair.generate()
    netData['manager1'] = mgr1.toString()
    netData['manager1_secret'] = netKeys['manager-1-secret']
    netData['managerApproval1'] = mgrApproval1.publicKey.toString()
    netData['managerApproval1_secret'] = exportSecretKey(mgrApproval1)

    const mch1 = anchor.web3.Keypair.generate()
    const mchApproval1 = anchor.web3.Keypair.generate()
    netData['merchant1'] = mch1.publicKey.toString()
    netData['merchant1_secret'] = exportSecretKey(mch1)
    netData['merchantApproval1'] = mchApproval1.publicKey.toString()
    netData['merchantApproval1_secret'] = exportSecretKey(mchApproval1)

    console.log('Create Auth Account')
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
                authData: authData.publicKey,
                systemProgram: SystemProgram.programId
            }
        }
    )

    console.log('Grant 1: Network Admin 1')
    await netAuthority.rpc.grant(
        rootData.nonce,
        0,
        {
            accounts: {
                program: netAuthorityPK,
                programAdmin: provider.wallet.publicKey,
                programData: new PublicKey(programData),
                rootData: new PublicKey(rootData.pubkey),
                authData: authData.publicKey,
                rbacUser: netAdminPK,
            },
        }
    )
    console.log('Grant 1 Done')

    console.log('Grant 2: Manager Admin 1')
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
                rbacUser: mgrAdminPK,
            },
        }
    )
    console.log('Grant 2 Done')

    console.log('Grant 3: Merchant Admin 1')
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
                rbacUser: mchAdminPK,
            },
        }
    )
    console.log('Grant 3 Done')

    console.log('Create Manager 1 Approval Account')
    const tx2 = new anchor.web3.Transaction()
    tx2.add(
        anchor.web3.SystemProgram.createAccount({
            fromPubkey: provider.wallet.publicKey,
            newAccountPubkey: mgrApproval1.publicKey,
            space: netAuthority.account.managerApproval.size,
            lamports: await provider.connection.getMinimumBalanceForRentExemption(netAuthority.account.managerApproval.size),
            programId: netAuthorityPK,
        })
    )
    await provider.send(tx2, [mgrApproval1])

    console.log('Create Merchant 1 Approval Account')
    const tx3 = new anchor.web3.Transaction()
    tx3.add(
        anchor.web3.SystemProgram.createAccount({
            fromPubkey: provider.wallet.publicKey,
            newAccountPubkey: mchApproval1.publicKey,
            space: netAuthority.account.merchantApproval.size,
            lamports: await provider.connection.getMinimumBalanceForRentExemption(netAuthority.account.merchantApproval.size),
            programId: netAuthorityPK,
        })
    )
    await provider.send(tx3, [mchApproval1])
 
    console.log('Approve Manager 1')
    await netAuthority.rpc.approveManager(
        rootData.nonce,
        {
            accounts: {
                rootData: new PublicKey(rootData.pubkey),
                authData: authData.publicKey,
                managerAdmin: mgrAdmin.publicKey,
                managerApproval: mgrApproval1.publicKey,
                managerKey: mgr1,
            },
            signers: [mgrAdmin],
        }
    )

    await jsonFileWrite('../../data/net.json', netData)
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
