#!/bin/bash

PAYER=/Users/mfrager/.config/solana/id.json
ROOT=/Users/mfrager/Build/solana/data

CFG_MINT=$ROOT/conf/usdv-mint-1.yml
KEY_TOKEN=$ROOT/export/key-usdv-token-1.json
KEY_FREEZE=$ROOT/export/key-usdv-freeze-1.json
PUB_TOKEN=$(solana-keygen pubkey $KEY_TOKEN)
PUB_FREEZE=$(solana-keygen pubkey $KEY_FREEZE)

spl-token create-token -C $CFG_MINT --decimals 4 --fee-payer $PAYER --enable-freeze -- $KEY_TOKEN
spl-token authorize -C $CFG_MINT --fee-payer $PAYER $PUB_TOKEN freeze $PUB_FREEZE 

echo -n "Token: "
echo $PUB_TOKEN

