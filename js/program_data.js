const { Buffer } = require('buffer')
const { DateTime } = require("luxon")
const { v4: uuidv4, parse: uuidparse } = require('uuid')
const { PublicKey, SystemProgram, SYSVAR_RENT_PUBKEY } = require('@solana/web3.js')
const { promisify } = require('util')
const exec = promisify(require('child_process').exec)

const anchor = require('@project-serum/anchor')
//const provider = anchor.Provider.env()
const provider = anchor.Provider.local()
anchor.setProvider(provider)
const netAuthority = anchor.workspace.NetAuthority
const netAuthorityPK = netAuthority.programId
//console.log(netAuthorityPK.toString())

async function main() {
    var jsres = await exec('solana program show --output json ' + netAuthorityPK.toString())
    var res = JSON.parse(jsres.stdout)
    var programData = res.programdataAddress
    console.log('Program Data: ' + programData)
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
