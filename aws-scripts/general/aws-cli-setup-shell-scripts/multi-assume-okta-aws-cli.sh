#!/bin/bash

# AWS CLI Setup Multi-Session Assume Role with Okta-AWS-CLI
# ---------------------------------------------------------
# The script uses okta-aws-cli to sign into Okta using a primary
# account and assumes into a given role within all other accounts
# mentioned in code. It uses the OIDC Client ID and federation
# app ID to write credentials into the default credentials file.


# Name of the role in other accounts that will be assumed
rolename="ROLE_TO_ASSUME"
sess_duration="3600"

echo "[default]
aws_access_key_id=""
aws_secret_access_key=""
" > ~/.aws/credentials

echo -n "" > profile_names
echo -n "" > account_names

# --write-aws-credentials writes to the ~/.aws/credentials file
okta-aws-cli --org-domain okta.ORG.com --oidc-client-id 0oaXXXXXXXXXXXX17 --aws-acct-fed-app-id 0oaYYYYYYYYYYYYp416 -s sess_duration --write-aws-credentials

# ---------------------------------------------------------------------

# Populate the array in this block in the format shown for all accounts
# that you need to assume a role in; part after : will be the profile name

# This can be done via AWS CLI and jq as follows:
# `aws organizations list-accounts --profile default > org-accounts.json`
# The profile above needs to be mfaprofile if the mfa is enforced
# `cat org-accounts.json | jq -r '.Accounts[] | "    \(.Id):\(.Name)"'`
# Then simply paste the values in

accounts=(
    "112233445566:staging"
    "223344556677:production"
)

# ---------------------------------------------------------------------

for account in "${accounts[@]}"
do
    IFS=":" read -ra acct <<< "$account"
    acct_num="${acct[0]}"
    alias="${acct[1]}"
    echo $alias >> profile_names
    echo "$acct_num:$alias" >> account_names
    values=$(aws sts assume-role --role-arn arn:aws:iam::$acct_num:role/$rolename --role-session-name $alias --profile default)
    ak=$(echo $values | jq '.Credentials.AccessKeyId' | tr -d "\"")
    sak=$(echo $values | jq '.Credentials.SecretAccessKey' | tr -d "\"")
    st=$(echo $values | jq '.Credentials.SessionToken' | tr -d "\"")
    echo "[$alias]
aws_access_key_id=$ak
aws_secret_access_key=$sak
aws_session_token=$st
" >> ~/.aws/credentials
    echo "Role in $alias assumed!"
done
