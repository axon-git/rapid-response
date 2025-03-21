#!/bin/bash

# Install GitHub CLI (Mac with Homebrew)
brew install gh

# Make sure you're authenticated
gh auth login

# Replace with your repo info
OWNER="your-org-or-username"
REPO="your-repo"
SINCE="2025-03-01T00:00:00Z"

# Create logs directory
mkdir -p logs

# Fetch workflow runs since target date and download logs
gh api repos/$OWNER/$REPO/actions/runs --paginate \
  --jq '.workflow_runs[] | select(.created_at >= "'"$SINCE"'") | .id' |
while read -r run_id; do
    echo "Downloading logs for run $run_id..."
    # Use curl instead of gh to avoid corrupted ZIPs
    LOG_URL="https://api.github.com/repos/$OWNER/$REPO/actions/runs/$run_id/logs"
    curl -sL -H "Authorization: Bearer $(gh auth token)" \
         -H "Accept: application/vnd.github+json" \
         "$LOG_URL" -o "logs/logs_$run_id.zip"
done
