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
//const netAuthority = anchor.workspace.NetAuthority
//const netAuthorityPK = netAuthority.programId

async function main() {
    const ataBytes = 165
    const ataRent = await provider.connection.getMinimumBalanceForRentExemption(ataBytes)

    const aprvBytes = 181
    const aprvRent = await provider.connection.getMinimumBalanceForRentExemption(aprvBytes)

    const infoBytes = 373
    const infoRent = await provider.connection.getMinimumBalanceForRentExemption(infoBytes)

    const totalRent = ataRent + aprvRent + infoRent
    const totalCost = totalRent + (0.00001 * 10**9 * 3)
    console.log("ATA Rent: " + ataRent)
    console.log("Approval Rent: " + aprvRent)
    console.log("Info Rent: " + infoRent)
    console.log("Total Rent: " + totalRent)
    console.log("Total Cost: " + totalCost)
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
