#Requires -Modules Az.Accounts, Az.Storage

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputFileName = "OneDriveSharedFiles_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

#-----------------------------------------------------------------------
# START: Recursive Function Definition
#-----------------------------------------------------------------------
function Get-RecursiveDriveItems {
    param(
        [string]$userId,
        [string]$userPrincipalName,
        [string]$displayName,
        [string]$mail,
        [string]$tenantDomain,
        [string]$authHeader,
        [string]$itemId = "root",
        [string]$parentPath = "/"
    )

    $itemsUri = "https://graph.microsoft.com/v1.0/users/$userId/drive/items/$itemId/children?`$top=999"
    
    do {
        try {
            $itemsResponse = Invoke-WebRequest -Uri $itemsUri -Method Get -Headers @{Authorization=$authHeader} -ContentType "application/json" -UseBasicParsing -ErrorAction Stop
            $itemsData = $itemsResponse.Content | ConvertFrom-Json
        }
        catch {
            # --- FIX 1 ---
            # Wrapped $parentPath in ${} to separate it from the colon
            Write-Warning "    Failed to get items in folder ${parentPath}: $($_.Exception.Message)"
            break # Stop this branch if we can't read it
        }

        foreach ($item in $itemsData.value) {
            # Build the full path for the current item
            $currentItemPath = ($parentPath + $item.name).Replace("//", "/") 
            
            # --- Get permissions for this item ---
            $permUri = "https://graph.microsoft.com/v1.0/users/$userId/drive/items/$($item.id)/permissions"
            
            try {
                $permResponse = Invoke-WebRequest -Uri $permUri -Method Get -Headers @{Authorization=$authHeader} -ContentType "application/json" -UseBasicParsing
                $perms = $permResponse.Content | ConvertFrom-Json
                
                if ($perms.value -and $perms.value.Count -gt 0) {
                    foreach ($perm in $perms.value) {
                        # Skip owner permissions without links
                        if ($perm.roles -contains "owner" -and -not $perm.link) { continue }
                        
                        # Initialize variables
                        $isExternal = $false
                        $sharedWith = ""
                        $sharedWithEmail = ""
                        $externalUsersList = @()
                        $internalUsersList = @()
                        $externalDomains = @()
                        
                        # Detect sharing type and recipients
                        if ($perm.link.scope -eq "anonymous") {
                            $isExternal = $true
                            $sharedWith = "Anyone with link (Anonymous)"
                            $sharedWithEmail = "ANONYMOUS_LINK"
                            $externalUsersList += "Anonymous Users"
                        }
                        elseif ($perm.grantedToIdentitiesV2) {
                            # Process grantedToIdentitiesV2 (multiple recipients)
                            foreach ($identity in $perm.grantedToIdentitiesV2) {
                                if ($identity.user) {
                                    $recipientEmail = $identity.user.email
                                    $recipientName = $identity.user.displayName
                                    
                                    if ($recipientEmail) {
                                        $recipientDomain = $recipientEmail.Split('@')[1]
                                        
                                        # Check if external
                                        if ($recipientDomain -ne $tenantDomain) {
                                            $isExternal = $true
                                            $externalUsersList += "$recipientName <$recipientEmail>"
                                            if ($recipientDomain -notin $externalDomains) {
                                                $externalDomains += $recipientDomain
                                            }
                                        }
                                        else {
                                            $internalUsersList += "$recipientName <$recipientEmail>"
                                        }
                                    }
                                    else {
                                        # No email available
                                        $externalUsersList += "$recipientName (Email not available)"
                                    }
                                }
                                elseif ($identity.group) {
                                    $internalUsersList += "Group: $($identity.group.displayName)"
                                }
                                elseif ($identity.application) {
                                    $internalUsersList += "Application: $($identity.application.displayName)"
                                }
                            }
                        }
                        elseif ($perm.grantedToV2) {
                            # Process grantedToV2 (single recipient)
                            if ($perm.grantedToV2.user) {
                                $recipientEmail = $perm.grantedToV2.user.email
                                $recipientName = $perm.grantedToV2.user.displayName
                                
                                if ($recipientEmail) {
                                    $recipientDomain = $recipientEmail.Split('@')[1]
                                    
                                    if ($recipientDomain -ne $tenantDomain) {
                                        $isExternal = $true
                                        $externalUsersList += "$recipientName <$recipientEmail>"
                                        $externalDomains += $recipientDomain
                                    }
                                    else {
                                        $internalUsersList += "$recipientName <$recipientEmail>"
                                    }
                                }
                                else {
                                    $externalUsersList += "$recipientName (Email not available)"
                                }
                            }
                            elseif ($perm.grantedToV2.group) {
                                $internalUsersList += "Group: $($perm.grantedToV2.group.displayName)"
                            }
                        }
                        elseif ($perm.grantedTo) {
                            # Legacy grantedTo format
                            if ($perm.grantedTo.user) {
                                $recipientEmail = $perm.grantedTo.user.email
                                $recipientName = $perm.grantedTo.user.displayName
                                
                                if ($recipientEmail) {
                                    $recipientDomain = $recipientEmail.Split('@')[1]
                                    
                                    if ($recipientDomain -ne $tenantDomain) {
                                        $isExternal = $true
                                        $externalUsersList += "$recipientName <$recipientEmail>"
                                        $externalDomains += $recipientDomain
                                    }
                                    else {
                                        $internalUsersList += "$recipientName <$recipientEmail>"
                                    }
                                }
                            }
                        }
                        elseif ($perm.link) {
                            # Sharing link without explicit recipients
                            if ($perm.link.scope -eq "organization") {
                                $sharedWith = "Anyone in organization"
                                $internalUsersList += "Organization-wide link"
                            }
                            elseif ($perm.link.scope -eq "users") {
                                $sharedWith = "Specific people (Details not available)"
                            }
                            else {
                                $sharedWith = "Shared link ($($perm.link.scope))"
                            }
                        }
                        
                        # Build final shared with strings
                        $allRecipients = @()
                        if ($externalUsersList.Count -gt 0) {
                            $allRecipients += $externalUsersList
                        }
                        if ($internalUsersList.Count -gt 0) {
                            $allRecipients += $internalUsersList
                        }
                        
                        if ($allRecipients.Count -gt 0) {
                            $sharedWith = $allRecipients -join "; "
                        }
                        
                        # Extract just emails for separate field
                        $sharedWithEmail = ($externalUsersList | ForEach-Object {
                            if ($_ -match '<(.+?)>') {
                                $matches[1]
                            }
                            elseif ($_ -eq "Anonymous Users") {
                                "ANONYMOUS"
                            }
                        }) -join "; "
                        
                        # Calculate risk
                        $riskScore = 0
                        if ($isExternal) { $riskScore += 5 }
                        if (-not $perm.expirationDateTime) { $riskScore += 3 }
                        if ($perm.link.scope -eq "anonymous") { $riskScore += 4 }
                        if ($perm.roles -contains "write") { $riskScore += 2 }
                        if ($externalUsersList.Count -gt 3) { $riskScore += 1 }
                        
                        $riskLevel = if ($riskScore -ge 10) { "Critical" }
                                    elseif ($riskScore -ge 7) { "High" }
                                    elseif ($riskScore -ge 4) { "Medium" }
                                    else { "Low" }
                        
                        
                        # Add to the global $results array
                        $script:results += [PSCustomObject]@{
                            Owner = $userPrincipalName
                            OwnerDisplayName = $displayName
                            OwnerEmail = $mail
                            FileName = $item.name
                            FilePath = $currentItemPath #<-- This now shows the full path
                            FileType = if ($item.file) { "File" } else { "Folder" }
                            FileSize = $item.size
                            FileSizeMB = [math]::Round($item.size / 1MB, 2)
                            SharedWith = $sharedWith
                            SharedWithEmail = $sharedWithEmail
                            ExternalUsers = ($externalUsersList -join "; ")
                            ExternalUserCount = $externalUsersList.Count
                            ExternalDomains = ($externalDomains -join "; ")
                            InternalUsers = ($internalUsersList -join "; ")
                            InternalUserCount = $internalUsersList.Count
                            LinkScope = $perm.link.scope
                            LinkType = $perm.link.type
                            PermissionType = ($perm.roles -join ", ")
                            PermissionId = $perm.id
                            HasExpirationDate = ($null -ne $perm.expirationDateTime)
                            ExpirationDateTime = $perm.expirationDateTime
                            HasPassword = if ($perm.hasPassword) { "Yes" } else { "No" }
                            IsExternalShare = $isExternal
                            RiskScore = $riskScore
                            RiskLevel = $riskLevel
                            WebUrl = $item.webUrl
                            CreatedDateTime = $item.createdDateTime
                            LastModifiedDateTime = $item.lastModifiedDateTime
                            ScanDateTime = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                        }
                        
                        # Debug output for external shares
                        if ($isExternal -and $externalUsersList.Count -gt 0) {
                            Write-Output "    🔴 External share detected: $currentItemPath"
                            Write-Output "       Recipients: $($externalUsersList -join ', ')"
                        }
                    }
                }
            }
            catch {
                # --- FIX 2 ---
                # Wrapped $currentItemPath in ${} to separate it from the colon
                Write-Warning "    Permission error for ${currentItemPath}: $($_.Exception.Message)"
            }
            
            # --- START: Recursive Call ---
            # If this item is a folder, call this function again to scan inside it
            if ($item.folder) {
                Write-Output "  -> Scanning subfolder: $currentItemPath"
                Get-RecursiveDriveItems -userId $userId `
                                        -userPrincipalName $userPrincipalName `
                                        -displayName $displayName `
                                        -mail $mail `
                                        -tenantDomain $tenantDomain `
                                        -authHeader $authHeader `
                                        -itemId $item.id `
                                        -parentPath ($currentItemPath + "/")
            }
            # --- END: Recursive Call ---
        }
        
        $itemsUri = $itemsData.'@odata.nextLink'
    } while ($itemsUri)
}
#-----------------------------------------------------------------------
# END: Recursive Function Definition
#-----------------------------------------------------------------------


# Get configuration
$tenantId = Get-AutomationVariable -Name 'OneDrive-TenantId'
$clientId = Get-AutomationVariable -Name 'OneDrive-ClientId'
$clientSecret = Get-AutomationVariable -Name 'OneDrive-ClientSecret'
$storageAccountName = Get-AutomationVariable -Name 'OneDrive-StorageAccountName'
$storageContainerName = Get-AutomationVariable -Name 'OneDrive-StorageContainerName'
$workspaceId = Get-AutomationVariable -Name 'OneDrive-WorkspaceId'
$workspaceKey = Get-AutomationVariable -Name 'OneDrive-WorkspaceKey'

# Clean variables
$tenantId = $tenantId.Trim()
$clientId = $clientId.Trim()
$clientSecret = $clientSecret.Trim()
$workspaceId = $workspaceId.Trim()
$workspaceKey = $workspaceKey.Trim()

$results = @()
$startTime = Get-Date

Write-Output "=========================================="
Write-Output "OneDrive Security Audit - Enhanced with External User Tracking"
Write-Output "Started: $startTime"
Write-Output "=========================================="

$tenantDomain = ""

try {
    # Get token
    Write-Output "`nAcquiring access token..."
    $tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
    
    $body = @{
        client_id     = $clientId
        scope         = "https://graph.microsoft.com/.default"
        client_secret = $clientSecret
        grant_type    = "client_credentials"
    }
    
    $tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
    $token = $tokenResponse.access_token
    Write-Output "Token acquired successfully"
    
    
    $authHeader = "Bearer $token"
    
    # Get organization domain
    Write-Output "Getting organization domain..."
    try {
        $orgResponse = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/organization" -Method Get -Headers @{Authorization=$authHeader} -ContentType "application/json" -UseBasicParsing
        $orgData = $orgResponse.Content | ConvertFrom-Json
        $tenantDomain = $orgData.value[0].verifiedDomains | Where-Object {$_.isDefault -eq $true} | Select-Object -ExpandProperty name
        Write-Output "Tenant domain: $tenantDomain"
    }
    catch {
        Write-Warning "Could not get tenant domain, will check manually"
    }
    
    # Get users
    Write-Output "`nRetrieving users..."
    $usersUri = "https://graph.microsoft.com/v1.0/users?`$select=id,userPrincipalName,displayName,mail&`$filter=accountEnabled eq true&`$top=999"
    
    $allUsers = @()
    do {
        $webResponse = Invoke-WebRequest -Uri $usersUri -Method Get -Headers @{Authorization=$authHeader} -ContentType "application/json" -UseBasicParsing
        $response = $webResponse.Content | ConvertFrom-Json
        $allUsers += $response.value
        $usersUri = $response.'@odata.nextLink'
    } while ($usersUri)
    
    Write-Output "Found $($allUsers.Count) active users"
    Write-Output "`nProcessing OneDrive drives..."
    
    $processedUsers = 0
    $usersWithOneDrive = 0
    
    foreach ($user in $allUsers) {
        $processedUsers++
        $percentComplete = [math]::Round(($processedUsers / $allUsers.Count) * 100, 2)
        Write-Output "[$processedUsers/$($allUsers.Count)] ($percentComplete%) Processing: $($user.userPrincipalName)"
        
        # Extract user's domain
        $userDomain = if ($user.mail) { $user.mail.Split('@')[1] } else { $user.userPrincipalName.Split('@')[1] }
        if (-not $tenantDomain) { $tenantDomain = $userDomain }
        
        try {
            # Check for OneDrive
            $driveUri = "https://graph.microsoft.com/v1.0/users/$($user.id)/drive"
            
            try {
                $driveResponse = Invoke-WebRequest -Uri $driveUri -Method Get -Headers @{Authorization=$authHeader} -ContentType "application/json" -UseBasicParsing -ErrorAction Stop
                $drive = $driveResponse.Content | ConvertFrom-Json
                
                if ($drive.id) {
                    $usersWithOneDrive++
                    Write-Output "  OneDrive found. Starting recursive scan..."
                    
                    # --- START: Modified section ---
                    # Call the new recursive function to scan the entire drive
                    Get-RecursiveDriveItems -userId $user.id `
                                            -userPrincipalName $user.userPrincipalName `
                                            -displayName $user.displayName `
                                            -mail $user.mail `
                                            -tenantDomain $tenantDomain `
                                            -authHeader $authHeader
                    # --- END: Modified section ---
                }
            }
            catch {
                if ($_.Exception.Response.StatusCode.value__ -ne 404) {
                    Write-Warning "  Error: $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-Warning "  Error processing user: $($_.Exception.Message)"
        }
        
        Start-Sleep -Milliseconds 200
    }
    
    # Statistics
    $endTime = Get-Date
    $duration = $endTime - $startTime
    $durationFormatted = "{0:D2}:{1:D2}:{2:D2}" -f $duration.Hours, $duration.Minutes, $duration.Seconds
    
    $externalNoExpiry = ($results | Where-Object {$_.IsExternalShare -eq $true -and $_.HasExpirationDate -eq $false}).Count
    $highRiskCount = ($results | Where-Object {$_.RiskLevel -eq "High" -or $_.RiskLevel -eq "Critical"}).Count
    $anonymousCount = ($results | Where-Object {$_.LinkScope -eq "anonymous"}).Count
    $uniqueExternalDomains = ($results | Where-Object {$_.ExternalDomains} | ForEach-Object {$_.ExternalDomains.Split('; ')} | Where-Object {$_} | Select-Object -Unique | Measure-Object).Count
    
    Write-Output "`n=========================================="
    Write-Output "PROCESSING COMPLETE"
    Write-Output "=========================================="
    Write-Output "Users processed: $processedUsers"
    Write-Output "Users with OneDrive: $usersWithOneDrive"
    Write-Output "Shared items found: $($results.Count)"
    Write-Output "External shares without expiry: $externalNoExpiry"
    Write-Output "High/Critical risk: $highRiskCount"
    Write-Output "Anonymous links: $anonymousCount"
    Write-Output "Unique external domains: $uniqueExternalDomains"
    Write-Output "Duration: $durationFormatted"
    Write-Output "=========================================="
    
    if ($results.Count -gt 0) {
        # Save CSV
        $tempPath = Join-Path $env:TEMP $OutputFileName
        $results | Export-Csv -Path $tempPath -NoTypeInformation -Encoding UTF8
        Write-Output "`nCSV created: $tempPath"
        
        # Show sample external shares
        $externalSamples = $results | Where-Object {$_.IsExternalShare -eq $true} | Select-Object -First 5
        if ($externalSamples) {
            Write-Output "`nSample External Shares:"
            foreach ($sample in $externalSamples) {
                Write-Output "  File: $($sample.FileName) (Path: $($sample.FilePath))"
                Write-Output "    Owner: $($sample.Owner)"
                Write-Output "    External Users: $($sample.ExternalUsers)"
                Write-Output "    External Domains: $($sample.ExternalDomains)"
                Write-Output "    Risk: $($sample.RiskLevel)"
                Write-Output ""
            }
        }
        
        # Upload to blob
        Write-Output "Uploading to blob storage..."
        try {
            $securePassword = ConvertTo-SecureString $clientSecret -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential($clientId, $securePassword)
            Connect-AzAccount -ServicePrincipal -Tenant $tenantId -Credential $credential -WarningAction SilentlyContinue | Out-Null
            
            $ctx = New-AzStorageContext -StorageAccountName $storageAccountName -UseConnectedAccount
            Set-AzStorageBlobContent -File $tempPath -Container $storageContainerName -Blob $OutputFileName -Context $ctx -Force | Out-Null
            
            Write-Output "Uploaded successfully"
            Disconnect-AzAccount -WarningAction SilentlyContinue | Out-Null
        }
        catch {
            Write-Warning "Upload failed: $($_.Exception.Message)"
        }
        
        # Send to Sentinel
        Write-Output "`nSending to Sentinel..."
        $batchSize = 500
        $totalBatches = [math]::Ceiling($results.Count / $batchSize)
        $sentSuccessfully = 0
        
        for ($i = 0; $i -lt $results.Count; $i += $batchSize) {
            $batch = $results[$i..[math]::Min($i + $batchSize - 1, $results.Count - 1)]
            $batchNum = [math]::Floor($i / $batchSize) + 1
            
            Write-Output "  Batch $batchNum of $totalBatches ($($batch.Count) records)..."
            
            try {
                $json = $batch | ConvertTo-Json -Depth 10
                $body = ([System.Text.Encoding]::UTF8.GetBytes($json))
                $method = "POST"
                $contentType = "application/json"
                $resource = "/api/logs"
                $rfc1123date = [DateTime]::UtcNow.ToString("r")
                $contentLength = $body.Length
                
                $xHeaders = "x-ms-date:" + $rfc1123date
                $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
                
                $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
                $keyBytes = [Convert]::FromBase64String($workspaceKey)
                
                $sha256 = New-Object System.Security.Cryptography.HMACSHA256
                $sha256.Key = $keyBytes
                $calculatedHash = $sha256.ComputeHash($bytesToHash)
                $encodedHash = [Convert]::ToBase64String($calculatedHash)
                $authorization = "SharedKey ${workspaceId}:${encodedHash}"
                
                $uri = "https://${workspaceId}.ods.opinsights.azure.com${resource}?api-version=2016-04-01"
                
                $headers = @{
                    "Authorization" = $authorization
                    "Log-Type" = "OneDriveSharedFiles"
                    "x-ms-date" = $rfc1123date
                    "time-generated-field" = "ScanDateTime"
                }
                
                Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing | Out-Null
                $sentSuccessfully += $batch.Count
            }
            catch {
                Write-Warning "Batch $batchNum failed: $($_.Exception.Message)"
            }
            
            Start-Sleep -Seconds 1
        }
        
        Write-Output "Sent $sentSuccessfully of $($results.Count) records to Sentinel"
        Remove-Item -Path $tempPath -Force -ErrorAction SilentlyContinue
    }
    else {
        Write-Output "`nNo shared files found."
    }
}
catch {
    Write-Error "Critical error: $($_.Exception.Message)"
    throw
}

Write-Output "`nCompleted at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"