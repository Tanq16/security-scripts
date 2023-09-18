#!/bin/bash

# AWS Multi-Session Assume Role
# -----------------------------
# The script creates an MFA session with the access keys of a user
# or uses the default session without MFA if there isn't an enforcement
# to refresh all role sessions across all accounts populated in code.
# It also saves all the profile names to `profile_names` and a mapping
# of `account_num:profile` to `account_names` in the current directory.


# Change these values:
# Set the user's access keys
echo "[default]
aws_access_key_id=""
aws_secret_access_key=""
" > ~/.aws/credentials
# Name of the role in other accounts that will be assumed
rolename=""

echo -n "" > profile_names
echo -n "" > account_names

# Comment this block if no user MFA is involved
# ---------------------------------------------------------------------

# Account number of the user that is assuming the role
assumer=""
# Name of MFA device for the user that is assuming
mfadev=""
# Read MFA token and create STS session with MFA set as true
read -p "MFA Code: " token
values=$(aws sts get-session-token --serial-number arn:aws:iam::$assumer:mfa/$mfadev --token-code $token)
ak=$(echo $values | jq '.Credentials.AccessKeyId' | tr -d "\"")
sak=$(echo $values | jq '.Credentials.SecretAccessKey' | tr -d "\"")
st=$(echo $values | jq '.Credentials.SessionToken' | tr -d "\"")
echo "[mfaprofile]
aws_access_key_id=$ak
aws_secret_access_key=$sak
aws_session_token=$st
" >> ~/.aws/credentials

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
    # using mfaprofile will limit sessions to 1 hour due to role chaining
    values=$(aws sts assume-role --role-arn arn:aws:iam::$acct_num:role/$rolename --role-session-name $alias --profile mfaprofile)
    # values=$(aws sts assume-role --role-arn arn:aws:iam::$acct_num:role/$rolename --duration-seconds 36000 --role-session-name $alias --profile default)
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
