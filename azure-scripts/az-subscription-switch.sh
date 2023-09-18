#!/bin/bash

subscriptionarr=$(az account list --query '[].name' -o tsv)

echo "Azure Subscriptions:"

IFS=$'\n' read -r -d '' -a subscriptions <<< "$subscriptionarr"

for i in $(seq 1 ${#subscriptions[@]}); do
    echo "$i. ${subscriptions[$i-1]}"
done

echo ""
read -p "Select subscription number to activate: " sub_number

az account set --subscription "${subscriptions[$sub_number-1]}"
