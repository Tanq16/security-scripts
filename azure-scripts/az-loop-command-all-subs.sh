#!/bin/bash

# Azure - Loop Command Over All Subscriptions
# -------------------------------------------
# This command takes in the input of a command that contains
# the substring `yyy` within it. The command is executed by
# the script across all subscriptions while replacing `yyy`
# with the lowercase, nno-special-char subcription name. One
# example is using an az subcommand while redirecting output
# to output-yyy.json.

subscriptionarr=$(az account list --query '[].name' -o tsv)

IFS=$'\n' read -r -d '' -a subscriptions <<< "$subscriptionarr"

read command

for i in "${subscriptions[@]}"; do
    az account set --subscription "$i"
    subs=$(echo "${i,,}" | tr -d " .,!#\$%^&()[];<>@")
    commandsubs="${command//yyy/$subs}"
    eval "$commandsubs"
    echo "."
done
