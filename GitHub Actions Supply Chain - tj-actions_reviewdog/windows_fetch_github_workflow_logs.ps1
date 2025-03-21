# Install GitHub CLI
winget install --id GitHub.cli

# Authenticate 
gh auth login

# Replace with your repo info
OWNER="your-org-or-username"
REPO="your-repo"
SINCE="2025-03-01T00:00:00Z"

# GitHub token from gh (must be authenticated)
$token = (gh auth token)

# Create logs directory
New-Item -ItemType Directory -Force -Path $LogFolder | Out-Null

# Fetch workflow runs
$workflowRunsJson = gh api "repos/$Owner/$Repo/actions/runs?per_page=100" --paginate
$workflowRuns = ($workflowRunsJson -join "`n" | ConvertFrom-Json).workflow_runs

foreach ($run in $workflowRuns) {
    $createdAt = Get-Date $run.created_at
    if ($createdAt -ge $Since) {
        $runId = $run.id
        $logUrl = "https://api.github.com/repos/$Owner/$Repo/actions/runs/$runId/logs"
        $zipPath = Join-Path $LogFolder "logs_$runId.zip"

        Write-Host "Downloading logs for run $runId ($createdAt)..."

        Invoke-WebRequest -Uri $logUrl `
                          -Headers @{ Authorization = "Bearer $token"; Accept = "application/vnd.github+json" } `
                          -OutFile $zipPath
    }
}
