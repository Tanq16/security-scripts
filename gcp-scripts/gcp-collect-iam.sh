#!/bin/bash

# GCP - IAM Data Collector
# ------------------------
# This bash script is aimed at collecting global information
# from a GCP organization, similar to the gaad-files in AWS.
# Specifically, it collects organization info, folders info,
# and info on each project. It then loops through all projects
# to get the IAM policy for all ancestors including itself.
# It then goes through all policies and gets descriptions for
# each role.

mkdir -p ./output
cd output

gcloud organizations list --format=json > organization-info.json
echo "[+] Collected organization info"

gcloud resource-manager folders list --organization $(cat organization-info.json | jq -r ".[].name" | cut -d "/" -f2) --format=json > folders.json
echo "[+] Collected folders info"

gcloud projects list --format=json > projects.json
echo "[+] Collected projects info"

# TODO: Add negative match to remove sys-* projects
for i in $(cat projects.json | jq -r '.[].projectId'); do gcloud projects get-ancestors-iam-policy "$i" --format=json > "project-$i.json"; echo -n "."; done; echo "."
echo "[+] Collected project ancestor policies"

for i in $(ls project-*.json); do cat $i | jq -r '.[].policy.bindings[].role'; done | sort -u | sed -E 's/^(.+)s\/(.+)\/roles\/(.+)$/\-\-\1=\2 \3/' > roles.list
echo "[+] Collected list of applicable roles"

echo "[@] Collecting roles info (takes a couple minutes)"
(echo "["; while read i; do eval "gcloud iam roles describe $i --format=json"; echo ","; done < roles.list | head -n -1; echo "]") > roles.json
echo "[+] Collected roles info"

jq -s '[.[] []]' project-*.json > projects-policies.json
echo "[*] Merged project ancestor policies"

rm project-*.json roles.list
cd ..

echo ""
echo "All output stored in the \`output\` directory. Execute \`python3 analysis.py\` to get privesc results."
