#!/bin/bash

# AWS GAAD Collector
# ------------------
# This scripts reads the profile_names file to get
# all profiles and then make a directory called gaads
# with the gaads of each account with the names intact.

mkdir -p gaads

while read -r line;
do
    aws iam get-account-authorization-details --profile "$line" > "gaads/$line-gaad.json"
done < profile_names
