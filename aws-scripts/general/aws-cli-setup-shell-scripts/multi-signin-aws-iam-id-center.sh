#!/bin/bash

# AWS CLI Setup Multi-Session IAM Identity Center
# -----------------------------------------------
# This script takes in IAM Identity Center SSO information and uses
# AWS CLI default SSO sign-in capabilities to setup sessions for all
# accounts setup in code. The SSO sign-in triggers a browser login
# flow, after which all account setups use the SSO session directly.


# CHANGE the URL and/or region to where Identity Center is deployed
# Information can be retrieved from IAM Identity Center landing page.
rolename="ROLENAME_TO_SIGN_INTO"
echo "[sso-session mysso]
sso_start_url = https://d-xxxxxxxxx.awsapps.com/start#
sso_region = eu-west-1
sso_registration_scopes = sso:account:access
" > ~/.aws/config

echo -n "" > profile_names
echo -n "" > account_names

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
    echo "[profile $alias]
sso_session = mysso
sso_account_id = $acct_num
sso_role_name = $rolename
" >> ~/.aws/config
    echo "Role for $alias added!"
done

# this step spits out (or opens) a URL and a code for device login flow
aws sso login --sso-session mysso
