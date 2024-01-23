#!/bin/bash

# AWS CLI Setup Multi-Okta SignIn with SAML2AWS
# ---------------------------------------------
# The script uses saml2aws to sign into Okta using the Okta
# identifiers taken from the Okta dashboard. MFA is set to
# Auto by deafult and the session duration is set to 10 hours.
# Does use credentials directly in the script, however some
# arguments can be removed to prompt for it. Generated session
# credentials are written to the default credentials file.


echo "[default]
aws_access_key_id=""
aws_secret_access_key=""
" > ~/.aws/credentials

# ---------------------------------------------------------------------
# FILL THIS SECTION IN

# Name of the role in other accounts that will be assumed
rolename="ROLE_TO_SIGN_INTO"
# Session Duration in seconds; may need to change to 3600 if failure is encountered.
sess_duration="36000"
# Credentials for Okta account
username="user@example.com"
password='h%@jas/!ds'

echo -n "" > profile_names
echo -n "" > account_names

# ---------------------------------------------------------------------
# Create the array of the format `okta-id:account-id:account-alias` for
# all accounts to be signed into. The okta-ids can be taken from the URL
# of the Okta apps from the Okta dashboard.

accounts=(
    "0oa2YYYYYYYYYYYYYYYY/272:111111111111:production"
    "0oa2XXXXXXXXXXXXXXXX/272:222222222222:staging"
)

# ---------------------------------------------------------------------

for account in "${accounts[@]}"
do
    IFS=":" read -ra acct <<< "$account"
    oktaid="${acct[0]}"
    acct_num="${acct[1]}"
    alias="${acct[2]}"
    echo $alias >> profile_names
    echo "$acct_num:$alias" >> account_names
    sleep 28 # needed to reset MFA TTL and for saml2aws to not cache incorrect token
    values=$(./saml2aws --idp-provider=Okta --quiet --mfa=Auto --url="https://upworkcorp.okta.com/home/amazon_aws/$oktaid" --username=$username --password=$password --skip-prompt --disable-keychain --role="arn:aws:iam::$acct_num:role/$rolename" login --credential-process --session-duration=$sess_duration --force --credentials-file=/dev/null)
    ak=$(echo $values | jq '.AccessKeyId' | tr -d "\"")
    sak=$(echo $values | jq '.SecretAccessKey' | tr -d "\"")
    st=$(echo $values | jq '.SessionToken' | tr -d "\"")
    echo "[$alias]
aws_access_key_id=$ak
aws_secret_access_key=$sak
aws_session_token=$st
" >> ~/.aws/credentials
    echo "Role in $alias assumed!"
done
