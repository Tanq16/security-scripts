#!/bin/bash

# Azure - Subscription Switcher
# -----------------------------
# This bash script is aimed at switching subsriptions. It
# provides a list of all subscriptions the current CLI user
# is capable of signing into. The user can select the serial
# number from the shown list and the script will set the
# associated subscription as active in the CLI session.

subscriptionarr=$(az account list --query '[].name' -o tsv)

echo "Azure Subscriptions:"

IFS=$'\n' read -r -d '' -a subscriptions <<< "$subscriptionarr"

for i in $(seq 1 ${#subscriptions[@]}); do
    echo "$i. ${subscriptions[$i-1]}"
done

echo ""
read -p "Select subscription number to activate: " sub_number

az account set --subscription "${subscriptions[$sub_number-1]}"
