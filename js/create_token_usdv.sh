#!/bin/bash

PAYER=/Users/mfrager/.config/solana/id.json
ROOT=/Users/mfrager/Build/solana/data

CFG_MINT=$ROOT/conf/usdv-mint-1.yml
KEY_TOKEN=$ROOT/export/key-usdv-token-1.json
KEY_MINT=$ROOT/export/key-usdv-mint-1.json
KEY_FREEZE=$ROOT/export/key-usdv-freeze-1.json
KEY_TREASURY=$ROOT/export/key-treasury-1.json
PUB_TOKEN=$(solana-keygen pubkey $KEY_TOKEN)
PUB_MINT=$(solana-keygen pubkey $KEY_MINT)
PUB_FREEZE=$(solana-keygen pubkey $KEY_FREEZE)
PUB_TREASURY=$(solana-keygen pubkey $KEY_TREASURY)
ATA_TREASURY=$(node print_ata.js $PUB_TOKEN $PUB_TREASURY)

spl-token create-token -C $CFG_MINT --decimals 4 --fee-payer $PAYER --enable-freeze -- $KEY_TOKEN
spl-token authorize -C $CFG_MINT --fee-payer $PAYER $PUB_TOKEN freeze $PUB_FREEZE 
spl-token create-account -C $CFG_MINT $PUB_TOKEN --fee-payer $PAYER --owner $PUB_TREASURY
spl-token mint -v -C $CFG_MINT --fee-payer $PAYER --mint-authority $KEY_MINT $PUB_TOKEN 1000000000000000 $ATA_TREASURY

echo -n "Token: "
echo $PUB_TOKEN

