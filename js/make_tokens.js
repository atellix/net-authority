const { promisify } = require('util')
const exec = promisify(require('child_process').exec)
const fs = require('fs').promises
const { jsonFileRead, jsonFileWrite } = require('../../js/atellix-common')

async function createTokenMint(mintName) {
    var res = await exec('./create_token_' + mintName + '.sh')
    return res.stdout
}

async function main() {
    const netKeys = await jsonFileRead('../../data/export/network_keys.json')

    var cres = await createTokenMint('usdv')
    console.log(cres)

    var tokens = {}
    tokens['tokenMintUSDV'] = netKeys['usdv-token-1-public']
    console.log('Created mint: usdv - ' + tokens['tokenMintUSDV'])

    //tokens['tokenMintUSDC'] = await createTokenMint('usdc')
    //console.log('Created mint: usdc - ' + tokens['tokenMintUSDC'])

    var res = await exec('spl-token create-account ' + tokens['tokenMintUSDV'] + ' --output json')
    console.log('Create account: usdv')
    console.log(res.stdout)

    //res = await exec('spl-token create-account ' + tokens['tokenMintUSDC'] + ' --output json')
    //console.log('Create account: usdc')
    //console.log(res.stdout)

    //testTokens = '1000000'
    //res = await exec('spl-token mint ' + tokens['tokenMintUSDC'] + ' ' + testTokens + ' --output json')
    //console.log('Mint test tokens: usdc - ' + testTokens)
    //console.log(res.stdout)

    //await jsonFileWrite('../../data/net.json', tokens)
}

console.log('Begin')
main().then(() => console.log('Success')).catch(error => {
    console.log(error)
})
