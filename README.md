# OneDriveforbusiness-Sentinel-Audit-external-sharing
PowerShell runbook for Azure Automation. Scans OneDrive recursively for external sharing and sends the audit log to Sentinel.

This PowerShell script is an Azure Automation runbook that recursively scans all user OneDrive accounts to find and audit shared files. It is designed to find external shares, calculate a risk score, and ingest the results into a Microsoft Sentinel Log Analytics workspace.
This script is an enhancement of simpler "root-only" scans and will traverse all subfolders to find shared items, providing a much more accurate security picture.

**Features**
Full Recursive Scan: Checks all files and subfolders in every user's OneDrive.

*External & Anonymous Share Detection*: Intelligently identifies shares with external domains (e.g., gmail.com) and anonymous "anyone with the link" shares.

*Automated Risk Scoring*: Assigns a "Critical," "High," "Medium," or "Low" risk level to each shared item based on factors like:

Is it shared externally?

Is it an anonymous link?

Does the share link ever expire?

Can the external person edit the file?

Microsoft Sentinel Integration: Ingests all findings directly into a custom log table (OneDriveSharedFiles_CL) for monitoring, alerting, and dashboarding.

Blob Storage Backup: Saves a full CSV copy of the audit report to Azure Blob Storage for long-term retention and compliance.

**How it Works**
Authenticates to Microsoft Graph using an App Registration (Service Principal).

Gets Tenant Domain: Finds your primary tenant domain (e.g., mycompany.com) to differentiate internal vs. external users.

Gets All Users: Iterates through every enabled user in the tenant.

Scans OneDrive Recursively: For each user, it starts at the root and drills down into every subfolder, checking the permissions on every file and folder it finds.

Uploads Results: Sends the final data (as a single large JSON array) to Azure Log Analytics in 500-record batches.

**Prerequisites**
You must set up the following components in Azure for this script to function.

1. App Registration (Service Principal)
This script runs non-interactively. You must create an App Registration in Azure AD / Entra ID and grant it the following Application-level permissions from the Microsoft Graph API:

Organization.Read.All: (To find your tenant's domain)

User.Read.All: (To get the list of users to scan)

Sites.Read.All: (Required to access OneDrive drive data)

2. Azure IAM Permissions
The App Registration also needs permission to write the CSV backup to your storage account.

Go to your Storage Account in the Azure portal.

Go to Access Control (IAM).

Grant the Storage Blob Data Contributor role to the App Registration (Service Principal) you just created.

3. Azure Automation Account
Create an Azure Automation Account.

Go to Modules (under "Shared Resources") and ensure the following modules are in your account. You may need to add them from the gallery.

Az.Accounts

Az.Storage

4. Automation Variables
In your Automation Account, go to Variables (under "Shared Resources") and create the following variables. These are the inputs the script uses.

OneDrive-TenantId: Your Azure tenant ID.

OneDrive-ClientId: The Application (client) ID for your App Registration.

OneDrive-ClientSecret: The client secret value for your App Registration. (Set this as Encrypted).

OneDrive-StorageAccountName: The name of your storage account for the CSV backup.

OneDrive-StorageContainerName: The container name (e.g., "onedrive-audits") in your storage account.

OneDrive-WorkspaceId: Your Log Analytics (Sentinel) Workspace ID.

OneDrive-WorkspaceKey: Your Log Analytics Workspace Primary Key. (Set this as Encrypted).

**How to Run**
Complete all steps in the Prerequisites section.

Import the ODFB-fileshare details.ps1 script into your Azure Automation Account as a new PowerShell Runbook.

Publish the runbook.

You can run the runbook manually by clicking Start, or set it up on a Schedule (e.g., to run every Sunday at 1 AM) for continuous monitoring.

**Viewing the Results**
In Microsoft Sentinel
The script sends data to a custom log named OneDriveSharedFiles. This will appear in your workspace as OneDriveSharedFiles_CL

**You can query the data in Sentinel with KQL:**
OneDriveSharedFiles_CL
| where IsExternalShare_b == true
| where RiskLevel_s == "Critical"
| project Owner_s, FileName_s, FilePath_s, ExternalUsers_s

**In Azure Storage**
A full CSV report named OneDriveSharedFiles_YYYYMMDD_HHmmss.csv will be saved in the storage account and container you specified in the variables.
