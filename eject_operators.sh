#!/bin/bash

addresses=(
    "0x066a0a1d576803172423dc0F8d79dFF858D78e4D"
    "0xfC3893d6213d75e3CE9934BE4546c9BcF2F48734"
    "0x526e2E9867590Bb0d6C8aa544FFaC88BE28A4181"
)

CONTRACT="0x3e43AA225b5cB026C5E8a53f62572b10D526a50B"
PRIVATE_KEY="c7697fdc93ad14a4b17d4865f2736393a19ba4a10e6306a6d327ecf528b61ef6"
RPC_URL="https://compatible-floral-sponge.ethereum-holesky.quiknode.pro/5208c2ae65694338de5f5a883442970cf04fefe0"

# Loop through each address
for address in "${addresses[@]}"; do
    echo "Ejecting operator: $address"

    # Execute the cast command and wait for it to complete
    cast send $CONTRACT "ejectOperator(address operator,bytes quorumNumbers)" \
        $address "0x00" \
        --private-key $PRIVATE_KEY \
        -r $RPC_URL

    # Check if the command was successful
    if [ $? -eq 0 ]; then
        echo "Successfully ejected $address"
    else
        echo "Failed to eject $address"
    fi

    # Add a small delay between transactions
    sleep 2
done 