#!/bin/bash

PAYER=/Users/mfrager/.config/solana/id.json
ROOT=/Users/mfrager/Build/solana/data

KEY_TOKEN_USDV=$ROOT/export/key-usdv-token-1.json
KEY_SWAP_FEES=$ROOT/export/key-swap-fees-1.json
KEY_MRCH_FEES=$ROOT/export/key-merchant-fees-1.json
KEY_TREASURY2=$ROOT/export/key-treasury-2.json

TOKEN_WSOL=So11111111111111111111111111111111111111112
TOKEN_USDC=Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr
TOKEN_USDV=$(solana-keygen pubkey $KEY_TOKEN_USDV)

PUB_SWAP_FEES=$(solana-keygen pubkey $KEY_SWAP_FEES)
PUB_MRCH_FEES=$(solana-keygen pubkey $KEY_MRCH_FEES)
PUB_TREASURY2=$(solana-keygen pubkey $KEY_TREASURY2)

# Swap Fees
echo 'Swap Fees'
spl-token create-account $TOKEN_WSOL --owner $PUB_SWAP_FEES
spl-token create-account $TOKEN_USDC --owner $PUB_SWAP_FEES
spl-token create-account $TOKEN_USDV --owner $PUB_SWAP_FEES

# Merchant Fees
echo 'Merchant Fees'
spl-token create-account $TOKEN_USDV --owner $PUB_MRCH_FEES

# Treasury 2
echo 'Treasury 2'
spl-token create-account $TOKEN_WSOL --owner $PUB_TREASURY2
spl-token create-account $TOKEN_USDC --owner $PUB_TREASURY2
spl-token create-account $TOKEN_USDV --owner $PUB_TREASURY2

