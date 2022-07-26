#####################################################
# HelloID-SA-Sync-Exchange-Online-DistributionGroup-To-Products
#
# Version: 1.1.0.0
#####################################################
$VerbosePreference = 'SilentlyContinue'
$informationPreference = 'Continue'
$WarningPreference = 'Continue'

# Make sure to create the Global variables defined below in HelloID
#HelloID Connection Configuration
$portalApiKey = $portalApiKey
$portalApiSecret = $portalApiSecret
$script:BaseUrl = $portalBaseUrl

#Target Connection Configuration     # Needed for accessing the Target System (These variables are also required for the Actions of each product)
$ExchangeOnlineAdminUsername = $ExchangeAdminUsername
$ExchangeOnlineAdminPassword = $ExchangeAdminPassword
$Filter = "DisplayName -like 'DistributionGroup*'" # Optional, when no filter is provided ($Filter = $null), all Cloud Distribution Groups will be queried

#HelloID Product Configuration
$ProductAccessGroup = 'Users'           # If not found, the product is created without extra Access Group
$ProductCategory = 'Distribution Groups'   # If the category is not found, it will be created
$SAProductResourceOwner = ''            # If left empty the groupname will be: "Resource owners [target-systeem] - [Product_Naam]")
$SAProductWorkflow = $null              # If empty. The Default HelloID Workflow is used. If specified Workflow does not exist the Product creation will raise an error.
$FaIcon = 'group'
$productVisibility = 'All'
$productRequestCommentOption = 'Hidden' # Define if comments can be added when requesting the product. Supported options: Optional, Hidden, Required
$returnProductOnUserDisable = $true # If True the product will be returned when the user owning the product gets disabled

$setDistributionGroupOwnerAsResourceOwner = $true # If True the owner(s) of the Distribution Group will be set as the Resource owner of the corresponding HelloID Self service Product. The user(s) and group(s) have to exist in HelloID to be able to be added to the Resource Owner group

$removeProduct = $true                  # If False product will be disabled
$overwriteExistingProduct = $false       # If True existing product will be overwritten with the input from this script (e.g. the approval worklow or icon). Only use this when you actually changed the product input
$overwriteExistingProductAction = $false # If True existing product actions will be overwritten with the input from this script. Only use this when you actually changed the script or variables for the action(s)


#Target System Configuration
# Dynamic property invocation
$uniqueProperty = 'GUID'              # The vaule of the property will be used as CombinedUniqueId

# [ValidateLength(4)]
$SKUPrefix = 'EXOG'                   # The prefix will be used as CombinedUniqueId. Max. 4 characters
$TargetSystemName = 'Exchange DistributionGroup'

$includeEmailAction = $true
$defaultFromAddress = "no-reply@helloid.com"
$defaultToAddress = "j.doe@eyoi.org"

#region HelloID
function Get-HIDDefaultAgentPool {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003036494-GET-Get-agent-pools
    #>
    [CmdletBinding()]
    param ()

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'GET'
            Uri    = 'agentpools'
        }
        Invoke-HIDRestMethod @splatParams
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-HIDSelfServiceProduct {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003027353-GET-Get-products
    #>
    [CmdletBinding()]
    param ()

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'GET'
            Uri    = 'selfservice/products'
        }
        Invoke-HIDRestMethod @splatParams
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-HIDSelfServiceProductAction {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003027353-GET-Get-products
    #>
    [CmdletBinding()]
    param ()

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'GET'
            Uri    = 'automationtasks'
        }
        Invoke-HIDRestMethod @splatParams
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-HIDSelfServiceCategory {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003036194-GET-Get-self-service-categories
    #>
    [CmdletBinding()]
    param ()

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'GET'
            Uri    = 'selfservice/categories'
        }
        Invoke-HIDRestMethod @splatParams
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Set-HIDSelfServiceProduct {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003038854-POST-Create-or-update-a-product
    #>
    [CmdletBinding()]
    param (
        $ProductJson
    )
    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Body   = $ProductJson
            Method = 'POST'
            uri    = 'selfservice/products'
        }
        Invoke-HIDRestMethod @splatParams
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function New-HIDSelfServiceCategory {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003024773-POST-Create-self-service-category
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Name,

        [string]
        $SelfServiceCategoryGUID,

        [bool]
        $IsEnabled
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $category = [ordered]@{
            "name"                    = $Name
            "SelfServiceCategoryGUID" = $SelfServiceCategoryGUID
            "isEnabled"               = $IsEnabled
        } | ConvertTo-Json

        $splatParams = @{
            Method = 'POST'
            Uri    = 'selfservice/categories'
            Body   = $category
        }
        Invoke-HIDRestMethod @splatParams
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Remove-HIDSelfServiceProduct {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003038654-DELETE-Delete-product
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $ProductGUID
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'DELETE'
            Uri    = "selfservice/products/$ProductGUID"
        }
        Invoke-HIDRestMethod @splatParams
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Add-HIDPowerShellAction {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/360013035680-POST-Create-or-update-PowerShell-task
    #>
    [CmdletBinding()]
    param(
        $body
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"

        $splatParams = @{
            Method = 'POST'
            Uri    = 'automationtasks/powershell'
            Body   = $body
        }
        Invoke-HIDRestMethod @splatParams
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Add-HIDEmailAction {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003036854-POST-Create-e-mail-action
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]
        $ProductGUID,

        [Parameter(Mandatory)]
        $body
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"

        $splatParams = @{
            Method = 'POST'
            Uri    = "selfservice/products/$($ProductGUID)/emailaction"
            Body   = $body
        }
        Invoke-HIDRestMethod @splatParams
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Remove-HIDAction {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003037034-DELETE-Delete-action
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]
        $ActionGUID
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"

        $splatParams = @{
            Method = 'DELETE'
            Uri    = "selfservice/actions/$ActionGUID"
        }
        Invoke-HIDRestMethod @splatParams
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}


function New-HIDGroup {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003038654-DELETE-Delete-product
    #>
    [Cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [string]
        $GroupName,

        [bool]
        $isEnabled
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $groupBody = @{
            name      = $GroupName
            isEnabled = $isEnabled
            userNames = ''
        } | ConvertTo-Json

        $splatParams = @{
            Method = 'POST'
            Uri    = 'groups'
            Body   = $groupBody
        }
        Invoke-HIDRestMethod @splatParams
    }
    catch {
        $Pscmdlet.ThrowTerminatingError($_)
    }
}


function Get-HIDGroup {
    <#
    .DESCRIPTION
       https://docs.helloid.com/hc/en-us/articles/115002981813-GET-Get-specific-group
    #>
    [Cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [string]
        $GroupName
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'GET'
            Uri    = "groups/$groupname"
        }
        Invoke-HIDRestMethod @splatParams
    }
    catch {
        if ($_.ErrorDetails.Message -match 'Group not found') {
            return $null
        }
        $Pscmdlet.ThrowTerminatingError($_)
    }
}

function Get-HIDGroups {
    <#
    .DESCRIPTION
       https://docs.helloid.com/hc/en-us/articles/115002994414-GET-Get-groups
    #>
    [Cmdletbinding()]
    param(
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"

        $splatParams = @{
            Method   = 'GET'
            Uri      = "groups"
            PageSize = 1000
        }

        Invoke-HIDRestMethod @splatParams
    }
    catch {
        $Pscmdlet.ThrowTerminatingError($_)
    }
}


function Get-HIDUsers {
    <#
    .DESCRIPTION
       https://docs.helloid.com/hc/en-us/articles/115002969074-GET-Get-all-users
    #>
    [Cmdletbinding()]
    param(
        [System.Nullable[boolean]]
        $IsEnabled = $null,

        [System.Nullable[boolean]]
        $IsDeleted = $null
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"

        $splatParams = @{
            Method   = 'GET'
            Uri      = "users"
            PageSize = 1000
        }

        if ($null -ne $IsEnabled) {
            if ($splatParams.Uri -match '\?') {
                $splatParams.Uri = $splatParams.Uri + "&enabled=$($IsEnabled)"
            }
            else {
                $splatParams.Uri = $splatParams.Uri + "?enabled=$($IsEnabled)"
            }
        }
        if ($null -ne $isDeleted) {
            if ($splatParams.Uri -match '\?') {
                $splatParams.Uri = $splatParams.Uri + "&isDeleted=$($IsDeleted)"
            }
            else {
                $splatParams.Uri = $splatParams.Uri + "?isDeleted=$($IsDeleted)"
            }
        }

        Invoke-HIDRestMethod @splatParams
    }
    catch {
        $Pscmdlet.ThrowTerminatingError($_)
    }
}

function Add-HIDProductMember {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115002954633-POST-Link-member-to-group
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $selfServiceProductGUID,

        [Parameter(Mandatory)]
        [string]
        $MemberGUID
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'POST'
            Uri    = "selfserviceproducts/$selfServiceProductGUID/groups"
            Body   = @{
                groupGUID = $MemberGUID
            } | ConvertTo-Json
        }
        Invoke-HIDRestMethod @splatParams
    }
    catch {
        $Pscmdlet.ThrowTerminatingError($_)
    }
}

function Add-HIDGroupMemberUser {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115002954633-POST-Link-member-to-group
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $GroupGUID,

        [Parameter(Mandatory)]
        [string]
        $MemberGUID
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'POST'
            Uri    = "groups/$GroupGUID/users"
            Body   = @{
                UserGUID = $MemberGUID
            } | ConvertTo-Json
        }
        Invoke-HIDRestMethod @splatParams
    }
    catch {
        $Pscmdlet.ThrowTerminatingError($_)
    }
}

function Add-HIDGroupMemberGroup {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115002954633-POST-Link-member-to-group
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $GroupGUID,

        [Parameter(Mandatory)]
        [string]
        $MemberGUID
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'POST'
            Uri    = "groups/$GroupGUID/membergroups"
            Body   = @{
                groupGUID = $MemberGUID
            } | ConvertTo-Json
        }
        Invoke-HIDRestMethod @splatParams
    }
    catch {
        $Pscmdlet.ThrowTerminatingError($_)
    }
}

function Add-HIDUserGroup {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115002954493-POST-Link-group-to-member
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $UserName,

        [Parameter()]
        [String]
        $GroupGuid
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatRestParameters = @{
            Method = 'POST'
            Uri    = "users/$UserName/groups"
            Body   = @{
                groupGUID = $GroupGuid
            } | ConvertTo-Json
        }
        Invoke-HIDRestMethod @splatRestParameters
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Invoke-HIDRestmethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Method,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Uri,

        [object]
        $Body,

        [string]
        $ContentType = 'application/json',

        [System.Nullable[int]]
        $PageSize = $null
    )

    try {
        Write-Verbose 'Switching to TLS 1.2'
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

        Write-Verbose 'Setting authorization headers'
        $apiKeySecret = "$($portalApiKey):$($portalApiSecret)"
        $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($apiKeySecret))
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Authorization", "Basic $base64")
        $headers.Add("Content-Type", $ContentType)

        $splatParams = @{
            Uri     = "$($script:BaseUrl)/api/v1/$Uri"
            Headers = $headers
            Method  = $Method
        }

        if ($null -ne $PageSize) {
            $skip = 0
            $take = $PageSize

            $splatParams.Uri = "$($script:BaseUrl)/api/v1/$Uri"
            if ($splatParams.Uri -match '\?') {
                $splatParams.Uri = $splatParams.Uri + "&skip=$Skip" + "&take=$take"
            }
            else {
                $splatParams.Uri = $splatParams.Uri + "?skip=$Skip" + "&take=$take"
            }
            Write-Verbose "Invoking '$Method' request to '$Uri'"
            $tempResult = Invoke-RestMethod @splatParams
            $result = $tempResult

            while ($tempResult.Count -eq $take) {
                $skip += $take

                $splatParams.Uri = "$($script:BaseUrl)/api/v1/$Uri"
                if ($splatParams.Uri -match '\?') {
                    $splatParams.Uri = $splatParams.Uri + "&skip=$Skip" + "&take=$take"
                }
                else {
                    $splatParams.Uri = $splatParams.Uri + "?skip=$Skip" + "&take=$take"
                }
        
                Write-Verbose "Invoking '$Method' request to '$Uri'"
                $tempResult = Invoke-RestMethod @splatParams
                $result += $tempResult
            }            
        }
        else {
            if ($Body) {
                Write-Verbose 'Adding body to request'
                $splatParams['Body'] = ([System.Text.Encoding]::UTF8.GetBytes($Body))
            }

            Write-Verbose "Invoking '$Method' request to '$Uri'"
            $result = Invoke-RestMethod @splatParams
        }

        Write-Output $result
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Write-HidStatus {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]
        $Message,

        [Parameter()]
        [String]
        $Event
    )
    if ([String]::IsNullOrEmpty($portalBaseUrl)) {
        Write-Information $Message
    }
    else {
        Hid-Write-Status -Message $Message -Event $Event
    }
}

function Write-HidSummary {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]
        $Message,

        [Parameter()]
        [String]
        $Event
    )

    if ([String]::IsNullOrEmpty($portalBaseUrl) -eq $true) {
        Write-Output ($Message)
    }
    else {
        Hid-Write-Summary -Message $Message -Event $Event
    }
}

function Compare-Join {
    [OutputType([array], [array], [array])]
    param(
        [parameter()]
        [string[]]$ReferenceObject,

        [parameter()]
        [string[]]$DifferenceObject
    )
    if ($null -eq $DifferenceObject) {
        $Left = $ReferenceObject
    }
    elseif ($null -eq $ReferenceObject ) {
        $right = $DifferenceObject
    }
    else {
        $left = [string[]][Linq.Enumerable]::Except($ReferenceObject, $DifferenceObject )
        $right = [string[]][Linq.Enumerable]::Except($DifferenceObject, $ReferenceObject)
        $common = [string[]][Linq.Enumerable]::Intersect($ReferenceObject, $DifferenceObject)
    }
    Write-Output $Left , $Right, $common
}

#endregion HelloID

#region HelloId_Actions_Variables
#region GroupMemberships
$AddGroupMembership = @'
#region functions
function Add-GroupMember {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $GroupName,
        [Parameter()]
        [String]
        $groupmember
    )
    try {
        # Import module
        $moduleName = "ExchangeOnlineManagement"
        $commands = @(
            "Get-User",
            "Get-DistributionGroup",
            "Add-DistributionGroupMember",
            "Remove-DistributionGroupMember",
            "Get-EXOMailbox",
            "Add-MailboxPermission",
            "Add-RecipientPermission",
            "Set-Mailbox",
            "Remove-MailboxPermission",
            "Remove-RecipientPermission"
        )

        # If module is imported say that and do nothing
        if (Get-Module | Where-Object { $_.Name -eq $ModuleName }) {
            Hid-Write-Status -Event Information -Message "Module $ModuleName is already imported."
        }
        else {
            # If module is not imported, but available on disk then import
            if (Get-Module -ListAvailable | Where-Object { $_.Name -eq $ModuleName }) {
                $module = Import-Module $ModuleName -Cmdlet $commands
                Hid-Write-Status -Event Information -Message "Imported module $ModuleName"
            }
            else {
                # If the module is not imported, not available and not in the online gallery then abort
                Hid-Write-Status -Event Failed -Message "Module $ModuleName not imported, not available. Please install the module using: Install-Module -Name $ModuleName -Force"
                Hid-Write-Summary -Event Failed -Message "Module $ModuleName not imported, not available. Please install the module using: Install-Module -Name $ModuleName -Force"
            }
        }

        # Check if Exchange Connection already exists
        try {
            $checkCmd = Get-User -ResultSize 1 -ErrorAction Stop | Out-Null
            $connectedToExchange = $true
        }
        catch {
            if ($_.Exception.Message -like "The term 'Get-User' is not recognized as the name of a cmdlet, function, script file, or operable program.*") {
                $connectedToExchange = $false
            }
        }
            
        # Connect to Exchange
        try {
            if ($connectedToExchange -eq $false) {
                Hid-Write-Status -Event Information -Message "Connecting to Exchange Online.."

                # Connect to Exchange Online in an unattended scripting scenario using user credentials (MFA not supported).
                $securePassword = ConvertTo-SecureString $ExchangeOnlineAdminPassword -AsPlainText -Force
                $credential = [System.Management.Automation.PSCredential]::new($ExchangeOnlineAdminUsername, $securePassword)
                $exchangeSessionParams = @{
                    Credential       = $credential
                    CommandName      = $commands
                    ShowBanner       = $false
                    ShowProgress     = $false
                    TrackPerformance = $false
                    ErrorAction      = 'Stop'
                }
                $exchangeSession = Connect-ExchangeOnline @exchangeSessionParams

                Hid-Write-Status -Event Success -Message "Successfully connected to Exchange Online"
            }
            else {
                Hid-Write-Status -Event Information -Message "Already connected to Exchange Online"
            }
        }
        catch {
            if (-Not [string]::IsNullOrEmpty($_.Exception.InnerExceptions)) {
                $errorMessage = "$($_.Exception.InnerExceptions)"
            }
            else {
                $errorMessage = "$($_.Exception.Message) $($_.ScriptStackTrace)"
            }
            Hid-Write-Status -Event Error -Message "Could not connect to Exchange Online, error: $errorMessage"
            Hid-Write-Summary -Event Failed -Message "Failed to connect to Exchange Online, error: $_"
        }

        # Add Send As Permissions
        $parameters = @{
            Identity        = $groupName
            Member          = $groupMember
            BypassSecurityGroupManagerCheck    = $true
        }
        $addPermission = Add-DistributionGroupMember @parameters -Confirm:$false -ErrorAction Stop
    }
    catch {
        if($_ -like "*already a member of the group*"){
            Hid-Write-Status -Event Warning -Message "The recipient $($parameters.Member) is already a member of the group $($parameters.Identity)"
        }else{
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }
    finally {
        Hid-Write-Status -Event Information -Message "Disconnecting from Exchange Online"
        Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
        Hid-Write-Status -Event Success -Message "Successfully disconnected from Exchange Online"
    }
}
#endregion functions
try {
    Hid-Write-Status -Event Information -Message "Adding user [$groupmember] to group [$groupName]"
    $null = Add-GroupMember -GroupName $groupName -GroupMember $GroupMember
    Hid-Write-Status -Event Success -Message "Succesfully added user [$groupmember] to group [$groupName]"
    Hid-Write-Summary -Event Success -Message "Succesfully added user [$groupmember] to group [$groupName]"
}
catch {
    Hid-Write-Status -Message  "Could not add user [$groupmember] to group [$groupName]. Error: $($_.Exception.Message)" -Event Error
    Hid-Write-Summary -Message "Could not add user [$groupmember] to group [$groupName]" -Event Failed
}
'@
$AddGroupMembershipAction = @{
    name                = 'Add-GroupMembership'
    automationContainer = 2
    objectGUID          = $null
    metaData            = '{"executeOnState":3}'
    useTemplate         = $false
    powerShellScript    = $AddGroupMembership
    variables           = @(
        @{
            "name"           = "GroupName"
            "value"          = "{{product.name}}"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "GroupMember"
            "value"          = "{{requester.username}}"
            "typeConstraint" = "string"
            "secure"         = $false
        }
    )
}

$RemoveGroupMembership = @'
#region functions
function Remove-GroupMember {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $GroupName,
        [Parameter()]
        [String]
        $groupmember
    )
    try {
        # Import module
        $moduleName = "ExchangeOnlineManagement"
        $commands = @(
            "Get-User",
            "Get-DistributionGroup",
            "Add-DistributionGroupMember",
            "Remove-DistributionGroupMember",
            "Get-EXOMailbox",
            "Add-MailboxPermission",
            "Add-RecipientPermission",
            "Set-Mailbox",
            "Remove-MailboxPermission",
            "Remove-RecipientPermission"
        )

        # If module is imported say that and do nothing
        if (Get-Module | Where-Object { $_.Name -eq $ModuleName }) {
            Hid-Write-Status -Event Information -Message "Module $ModuleName is already imported."
        }
        else {
            # If module is not imported, but available on disk then import
            if (Get-Module -ListAvailable | Where-Object { $_.Name -eq $ModuleName }) {
                $module = Import-Module $ModuleName -Cmdlet $commands
                Hid-Write-Status -Event Information -Message "Imported module $ModuleName"
            }
            else {
                # If the module is not imported, not available and not in the online gallery then abort
                Hid-Write-Status -Event Failed -Message "Module $ModuleName not imported, not available. Please install the module using: Install-Module -Name $ModuleName -Force"
                Hid-Write-Summary -Event Failed -Message "Module $ModuleName not imported, not available. Please install the module using: Install-Module -Name $ModuleName -Force"
            }
        }

        # Check if Exchange Connection already exists
        try {
            $checkCmd = Get-User -ResultSize 1 -ErrorAction Stop | Out-Null
            $connectedToExchange = $true
        }
        catch {
            if ($_.Exception.Message -like "The term 'Get-User' is not recognized as the name of a cmdlet, function, script file, or operable program.*") {
                $connectedToExchange = $false
            }
        }
            
        # Connect to Exchange
        try {
            if ($connectedToExchange -eq $false) {
                Hid-Write-Status -Event Information -Message "Connecting to Exchange Online.."

                # Connect to Exchange Online in an unattended scripting scenario using user credentials (MFA not supported).
                $securePassword = ConvertTo-SecureString $ExchangeOnlineAdminPassword -AsPlainText -Force
                $credential = [System.Management.Automation.PSCredential]::new($ExchangeOnlineAdminUsername, $securePassword)
                $exchangeSessionParams = @{
                    Credential       = $credential
                    CommandName      = $commands
                    ShowBanner       = $false
                    ShowProgress     = $false
                    TrackPerformance = $false
                    ErrorAction      = 'Stop'
                }
                $exchangeSession = Connect-ExchangeOnline @exchangeSessionParams

                Hid-Write-Status -Event Success -Message "Successfully connected to Exchange Online"
            }
            else {
                Hid-Write-Status -Event Information -Message "Already connected to Exchange Online"
            }
        }
        catch {
            if (-Not [string]::IsNullOrEmpty($_.Exception.InnerExceptions)) {
                $errorMessage = "$($_.Exception.InnerExceptions)"
            }
            else {
                $errorMessage = "$($_.Exception.Message) $($_.ScriptStackTrace)"
            }
            Hid-Write-Status -Event Error -Message "Could not connect to Exchange Online, error: $errorMessage"
            Hid-Write-Summary -Event Failed -Message "Failed to connect to Exchange Online, error: $_"
        }

        # Add Send As Permissions
        $parameters = @{
            Identity        = $groupName
            Member          = $groupMember
            BypassSecurityGroupManagerCheck    = $true
        }
        $removePermission = Remove-DistributionGroupMember @parameters -Confirm:$false -ErrorAction Stop
    }
    catch {
        if($_ -like "*isn't a member of the group*"){
            Hid-Write-Status -Event Warning -Message "The recipient $($parameters.Member) is not a member of the group $($parameters.Identity)"
        }elseif($_ -like "*object '*' couldn't be found*"){
            Hid-Write-Status -Event Warning -Message "Group $($parameters.Identity) couldn't be found. Possibly no longer exists. Skipping action"
        }elseif($_ -like "*Couldn't find object ""*""*"){
            Hid-Write-Status -Event Warning -Message "User $($parameters.Member) couldn't be found. Possibly no longer exists. Skipping action"
        }else{
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }
    finally {
        Hid-Write-Status -Event Information -Message "Disconnecting from Exchange Online"
        Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
        Hid-Write-Status -Event Success -Message "Successfully disconnected from Exchange Online"
    }
}
#endregion functions
try {
    Hid-Write-Status -Event Information -Message "Removing user [$groupmember] from group [$groupName]"
    $null = Remove-GroupMember -GroupName $groupName -GroupMember $GroupMember
    Hid-Write-Status -Event Success -Message "Succesfully removed user [$groupmember] from group [$groupName]"
    Hid-Write-Summary -Event Success -Message "Succesfully removed user [$groupmember] from group [$groupName]"
}
catch {
    Hid-Write-Status -Message  "Could not remove user [$groupmember] from group [$groupName]. Error: $($_.Exception.Message)" -Event Error
    Hid-Write-Summary -Message "Could not remove user [$groupmember] from group [$groupName]" -Event Failed
}
'@
$RemoveGroupMembershipAction = @{
    name                = 'Remove-GroupMembership'
    automationContainer = 2
    objectGUID          = $null
    metaData            = '{"executeOnState":11}'
    useTemplate         = $false
    powerShellScript    = $RemoveGroupMembership
    variables           = @(
        @{
            "name"           = "GroupName"
            "value"          = "{{product.name}}"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "GroupMember"
            "value"          = "{{requester.username}}"
            "typeConstraint" = "string"
            "secure"         = $false
        }
    )
}
#endregion SendAsRights

#region Emails
$ApproveEmailContent = '
Dear Servicedesk,
The product {{product.name}} has sucesfully been granted to {{requester.fullName}}.
Kind regards,
HelloID
'
$ApproveEmailAction = @{
    executeOnState = 3
    variables      = @(
        @{
            "name"           = "to"
            "value"          = "$defaultToAddress"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "from"
            "value"          = "$defaultFromAddress"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "subject"
            "value"          = "HelloID - Successfully granted product {{product.name}} to {{requester.fullName}}"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "content"
            "value"          = $ApproveEmailContent
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "isHtmlContent"
            "value"          = $true
            "typeConstraint" = "boolean"
            "secure"         = $false
        }
    )
}

$ReturnEmailContent = '
Dear Servicedesk,

The product {{product.name}} has sucesfully been revoked for {{requester.fullName}}.

Kind regards,
HelloID
'
$ReturnEmailAction = @{
    executeOnState = 11
    variables      = @(
        @{
            "name"           = "to"
            "value"          = "$defaultToAddress"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "from"
            "value"          = "$defaultFromAddress"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "subject"
            "value"          = "HelloID - Successfully revoked product {{product.name}} for {{requester.fullName}}"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "content"
            "value"          = $ReturnEmailContent
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "isHtmlContent"
            "value"          = $true
            "typeConstraint" = "boolean"
            "secure"         = $false
        }
    )
}
#endregion Emails

#endregion HelloId_Actions_Variables

#region script
try {
    # Import module
    $moduleName = "ExchangeOnlineManagement"
    $commands = @(
        "Get-User",
        "Get-Group",
        "Get-DistributionGroup",
        "Add-DistributionGroupMember",
        "Remove-DistributionGroupMember",
        "Get-EXOMailbox",
        "Add-MailboxPermission",
        "Add-RecipientPermission",
        "Set-Mailbox",
        "Remove-MailboxPermission",
        "Remove-RecipientPermission"
    )
 
    # If module is imported say that and do nothing
    if (Get-Module | Where-Object { $_.Name -eq $ModuleName }) {
        Write-HidStatus -Event Information -Message "Module $ModuleName is already imported."
    }
    else {
        # If module is not imported, but available on disk then import
        if (Get-Module -ListAvailable | Where-Object { $_.Name -eq $ModuleName }) {
            $module = Import-Module $ModuleName -Cmdlet $commands
            Write-HidStatus -Event Information -Message "Imported module $ModuleName"
        }
        else {
            # If the module is not imported, not available and not in the online gallery then abort
            Write-HidStatus -Event Failed -Message "Module $ModuleName not imported, not available. Please install the module using: Install-Module -Name $ModuleName -Force"
            Write-HidSummary -Event Failed -Message "Module $ModuleName not imported, not available. Please install the module using: Install-Module -Name $ModuleName -Force"
        }
    }
 
    # Check if Exchange Connection already exists
    try {
        $checkCmd = Get-User -ResultSize 1 -ErrorAction Stop | Out-Null
        $connectedToExchange = $true
    }
    catch {
        if ($_.Exception.Message -like "The term 'Get-User' is not recognized as the name of a cmdlet, function, script file, or operable program.*") {
            $connectedToExchange = $false
        }
    }
             
    # Connect to Exchange
    try {
        if ($connectedToExchange -eq $false) {
            Write-HidStatus -Event Information -Message "Connecting to Exchange Online.."
 
            # Connect to Exchange Online in an unattended scripting scenario using user credentials (MFA not supported).
            $securePassword = ConvertTo-SecureString $ExchangeOnlineAdminPassword -AsPlainText -Force
            $credential = [System.Management.Automation.PSCredential]::new($ExchangeOnlineAdminUsername, $securePassword)
            $exchangeSessionParams = @{
                Credential       = $credential
                CommandName      = $commands
                ShowBanner       = $false
                ShowProgress     = $false
                TrackPerformance = $false
                ErrorAction      = 'Stop'
            }
            $exchangeSession = Connect-ExchangeOnline @exchangeSessionParams
 
            Write-HidStatus -Event Success -Message "Successfully connected to Exchange Online"
        }
        else {
            Write-HidStatus -Event Information -Message "Already connected to Exchange Online"
        }
    }
    catch {
        if (-Not [string]::IsNullOrEmpty($_.Exception.InnerExceptions)) {
            $errorMessage = "$($_.Exception.InnerExceptions)"
        }
        else {
            $errorMessage = "$($_.Exception.Message) $($_.ScriptStackTrace)"
        }
        Write-HidStatus -Event Error -Message "Could not connect to Exchange Online, error: $errorMessage"
        Write-HidSummary -Event Failed -Message "Failed to connect to Exchange Online, error: $_"
    }

    try {
        # Only get Exchange Groups (Mail-enabled Security Group of Distribution Group)
        # Do not get all groups using "Get-Group", since we cannot manage Microsoft 365 or Security Groups (they have to be managed from Azure AD) 
        # Filter Cloud-Only groups (IsDirSynced -eq 'False')
        Write-HidStatus -Event Information -Message "Querying Exchange Distribution Groups"

        $parameters = @{
            Filter     = "IsDirSynced -eq 'False'"
            ResultSize = "Unlimited"
        }
        # Enhance Filter when provided
        if ($null -ne $Filter) {
            $parameters.Filter += " -and ($Filter)"
        }
        $exchangeGroups = Get-DistributionGroup @parameters -ErrorAction Stop

        $TargetGroups = $exchangeGroups
        # $TargetGroups = $null              #easy way to remove all products

        Write-HidStatus -Event Success -Message "Succesfully queried Exchange Distribution Groups. Result count: $($exchangeGroups.id.Count)"

        if ($true -eq $setDistributionGroupOwnerAsResourceOwner) {
            Write-HidStatus -Event Information -Message "Querying Exchange Users"

            $parameters = @{
                ResultSize = "Unlimited"
            }
            $exchangeUsers = Get-User @parameters -ErrorAction Stop
            $exchangeUsersGrouped = $exchangeUsers | Group-Object -Property 'identity' -AsHashTable -AsString
    
            Write-HidStatus -Event Success -Message "Succesfully queried Exchange Users. Result count: $($exchangeUsers.id.Count)"

            # Query all groups, since owners can also be (in theory) other type of groups
            Write-HidStatus -Event Information -Message "Querying Exchange groups"

            $parameters = @{
                ResultSize = "Unlimited"
            }
            $exchangeGroups = Get-Group @parameters -ErrorAction Stop
            $exchangeGroupsGrouped = $exchangeGroups | Group-Object -Property 'identity' -AsHashTable -AsString
    
            Write-HidStatus -Event Success -Message "Succesfully queried Exchange groups. Result count: $($exchangeGroups.id.Count)"

        }
    }
    catch {
        if (-Not [string]::IsNullOrEmpty($_.Exception.InnerExceptions)) {
            $errorMessage = "$($_.Exception.InnerExceptions)"
        }
        else {
            $errorMessage = "$($_.Exception.Message) $($_.ScriptStackTrace)"
        }
        Write-HidStatus -Event Error -Message "Could not query Exchange Distribution Groups, error: $errorMessage"
        Write-HidSummary -Event Failed -Message "Failed to query Exchange Distribution Groups, error: $_"
    }
    finally {
        Write-HidStatus -Event Information -Message "Disconnecting from Exchange Online"
        Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
        Write-HidStatus -Event Success -Message "Successfully disconnected from Exchange Online"
    }

    Write-HidStatus -Message 'Starting synchronization of TargetSystem groups to HelloID products' -Event Information
    Write-HidStatus -Message "------[$TargetSystemName]-----------" -Event Information
    if ($TargetGroups.count -gt 0) {
        if ($null -eq $TargetGroups.$uniqueProperty) {
            throw "The specified unique property [$uniqueProperty] for the target system does exist as property in the groups"
        }
    }

    if ($TargetGroups.Count -eq 0) {
        Write-HidStatus -Message 'No Target Groups have been found' -Event Information
    }
    else {
        Write-HidStatus -Message "[$($TargetGroups.Count)] Target group(s)" -Event Information
    }

    $targetGroupsList = [System.Collections.Generic.List[Object]]::New()
    foreach ($group in $TargetGroups) {
        $tempGroup = $group | Select-Object *
        $tempGroup | Add-Member @{
            CombinedUniqueId = $SKUPrefix + "$($group.$uniqueProperty)".Replace('-', '')
        }
        # Optional, override product name
        $tempGroup.name = $tempGroup.DisplayName

        $targetGroupsList.Add($tempGroup)
    }
    $TargetGroups = $targetGroupsList
    $TargetGroupsGrouped = $TargetGroups | Group-Object -Property CombinedUniqueId -AsHashTable -AsString

    Write-HidStatus -Message '------[HelloID]-----------------------' -Event Information
    Write-HidStatus -Message 'Getting default agent pool' -Event Information
    $defaultAgentPool = (Get-HIDDefaultAgentPool) | Where-Object { $_.options -eq '1' }

    Write-HidStatus -Message "Gathering the self service product category '$ProductCategory'" -Event Information
    $selfServiceCategory = (Get-HIDSelfServiceCategory) | Where-Object { $_.name -eq "$ProductCategory" }

    if ($selfServiceCategory.isEnabled -eq $false) {
        Write-HidStatus -Message "Found a disabled ProductCategory '$ProductCategory', will enable the current category" -Event Information
        $selfServiceCategory = New-HIDSelfServiceCategory -Name "$ProductCategory" -IsEnabled $true -SelfServiceCategoryGUID  $selfServiceCategory.selfServiceCategoryGUID
    }
    elseif ($null -eq $selfServiceCategory) {
        Write-HidStatus -Message "No ProductCategory Found will Create a new category '$ProductCategory'" -Event Information
        $selfServiceCategory = New-HIDSelfServiceCategory -Name "$ProductCategory" -IsEnabled $true
    }

    Write-HidStatus -Message 'Gathering Self service products from HelloID' -Event Information
    $selfServiceProduct = Get-HIDSelfServiceProduct
    $selfServiceProductGrouped = $selfServiceProduct | Group-Object -Property 'code' -AsHashTable -AsString

    Write-HidStatus -Message 'Gathering Self service product actions from HelloID' -Event Information
    $selfServiceProductAction = Get-HIDSelfServiceProductAction
    $selfServiceProductActionGrouped = $selfServiceProductAction | Group-Object -Property 'objectGuid' -AsHashTable -AsString

    if ($true -eq $setDistributionGroupOwnerAsResourceOwner) {
        Write-HidStatus -Message 'Gathering users from HelloID' -Event Information
        $selfServiceUsers = Get-HIDUsers
        $selfServiceUsersGrouped = $selfServiceUsers | Group-Object -Property 'username' -AsHashTable -AsString

        Write-HidStatus -Message 'Gathering groups from HelloID' -Event Information
        $selfServiceGroups = Get-HIDGroups
        $selfServiceGroupsGrouped = $selfServiceGroups | Group-Object -Property 'name' -AsHashTable -AsString
    }

    Write-HidStatus -Message '------[Summary]-----------------------' -Event Information
    Write-HidStatus -Message "Total HelloID Self Service Product(s) found [$($selfServiceProduct.Count)]" -Event Information

    # Making sure we only manage the products of Target System
    $currentProducts = $selfServiceProduct | Where-Object { $_.code.ToLower().startswith("$($SKUPrefix.tolower())") }

    Write-HidStatus -Message "HelloID Self Service Product(s) of Target System [$TargetSystemName] found [$($currentProducts.Count)]" -Event Information

    # Null Check Reference before compare
    $currentProductsChecked = if ($null -ne $currentProducts.code) { $currentProducts.code.tolower() } else { $null }
    $targetGroupsChecked = if ($null -ne $TargetGroups.CombinedUniqueId) { $TargetGroups.CombinedUniqueId.ToLower() } else { $null }

    $productToCreateInHelloID , $productToRemoveFromHelloID, $productExistsInHelloID = Compare-Join -ReferenceObject $targetGroupsChecked -DifferenceObject $currentProductsChecked
    Write-HidStatus "[$($productToCreateInHelloID.count)] Products will be Created " -Event Information
    Write-HidStatus "[$($productExistsInHelloID.count)] Products already exist in HelloId" -Event Information
    if ($removeProduct) {
        Write-HidStatus "[$($productToRemoveFromHelloID.count)] Products will be Removed " -Event Information
    }
    else {
        Write-HidStatus 'Verify if there are products found which are already disabled.' -Event Information
        $productToRemoveFromHelloID = [array]($currentProducts | Where-Object { ( $_.code.ToLower() -in $productToRemoveFromHelloID) -and $_.visibility -ne 'Disabled' }).code
        Write-HidStatus "[$($productToRemoveFromHelloID.count)] Products will be disabled " -Event Information
    }

    Write-HidStatus -Message '------[Processing]------------------' -Event Information
    foreach ($productToCreate in $productToCreateInHelloID) {
        $product = $TargetGroupsGrouped[$productToCreate]
        Write-HidStatus "Creating Product [$($product.name)]" -Event Information
        $resourceOwnerGroupName = if ([string]::IsNullOrWhiteSpace($SAProductResourceOwner) ) { "$($product.name) Resource Owners" } else { $SAProductResourceOwner }

        $resourceOwnerGroup = Get-HIDGroup -GroupName $resourceOwnerGroupName
        if ($null -eq $resourceOwnerGroup ) {
            Write-HidStatus "Creating a new resource owner group for Product [$($resourceOwnerGroupName)]" -Event Information
            $resourceOwnerGroup = New-HIDGroup -GroupName $resourceOwnerGroupName -isEnabled $true
        }

        
        if ($true -eq $setDistributionGroupOwnerAsResourceOwner) {
            if ($null -eq $product.managedBy) {
                Write-HidStatus "No owners found of Exchange Distribution Group [$($product.name)]" -Event Information
            }
            else {
                Write-HidStatus "Setting owners of Exchange Distribution Group [$($product.name)] as members of HelloID Resource Owner Group [$($resourceOwnerGroup.name)]" -Event Information

                $distributionGroupOwners = $product.managedBy
                foreach ($distributionGroupOwner in $distributionGroupOwners) {
                    # Owners can be either groups or users or a combination of both, therefore, check both

                    # Check for user
                    $exchangeUser = $exchangeUsersGrouped[$distributionGroupOwner]
                    if ($null -ne $exchangeUser) {
                        $helloIDUser = $selfServiceUsersGrouped[$($exchangeUser.UserPrincipalName)]
                        if ($null -ne $helloIDUser) {
                            $null = Add-HIDGroupMemberUser -GroupGUID $resourceOwnerGroup.groupGuid -MemberGUID $helloIDUser.userGUID
                        }
                    }
                    else {
                        # Check for group
                        $exchangeGroup = $exchangeGroupsGrouped[$distributionGroupOwner]
                        if ($null -ne $exchangeGroup) {
                            $helloIDGroup = $selfServiceGroupsGrouped[$($exchangeGroup.Name)]
                            if ($null -ne $helloIDGroup) {
                                $null = Add-HIDGroupMemberGroup -GroupGUID $resourceOwnerGroup.groupGuid -MemberGUID $helloIDGroup.groupGUID
                            }
                        }
                    }
                }
            }
        }

        $productBody = @{
            Name                       = "$($product.displayName)"
            Description                = "$TargetSystemName - $($product.displayName)"
            ManagedByGroupGUID         = $($resourceOwnerGroup.groupGuid)
            Categories                 = @($selfServiceCategory.name)
            ApprovalWorkflowName       = $SAProductWorkflow
            AgentPoolGUID              = $defaultAgentPool.agentPoolGUID
            Icon                       = $null
            FaIcon                     = "fa-$FaIcon"
            UseFaIcon                  = $true
            IsAutoApprove              = $false
            IsAutoDeny                 = $false
            MultipleRequestOption      = 1
            HasTimeLimit               = $false
            LimitType                  = 'Fixed'
            ManagerCanOverrideDuration = $true
            ReminderTimeout            = 30
            OwnershipMaxDuration       = 90
            CreateDefaultEmailActions  = $true
            Visibility                 = $productVisibility
            RequestCommentOption       = $productRequestCommentOption
            ReturnOnUserDisable        = $returnProductOnUserDisable
            Code                       = $product.CombinedUniqueId
        } | ConvertTo-Json
        $selfServiceProduct = Set-HIDSelfServiceProduct -ProductJson $productBody

        $sAAccessGroup = Get-HIDGroup -GroupName $ProductAccessGroup
        if (-not $null -eq $sAAccessGroup) {
            Write-HidStatus -Message  "Adding ProductAccessGroup [$ProductAccessGroup] to Product " -Event Information
            $null = Add-HIDProductMember -selfServiceProductGUID $selfServiceProduct.selfServiceProductGUID -MemberGUID $sAAccessGroup.groupGuid
        }
        else {
            Write-HidStatus -Message  "The Specified ProductAccessGroup [$ProductAccessGroup] does not exist. We will continue without adding the access Group" -Event Warning
        }

        $PowerShellActions = [System.Collections.Generic.list[object]]@(
            $AddGroupMembershipAction
            $RemoveGroupMembershipAction
        )

        foreach ($PowerShellAction in $PowerShellActions) {
            Write-HidStatus -Message  "Adding PowerShell action [$($PowerShellAction.Name)] to Product" -Event Information
            $PowerShellAction.objectGUID = $selfServiceProduct.selfServiceProductGUID
            $null = Add-HIDPowerShellAction -Body ($PowerShellAction | ConvertTo-Json)
        }

        if ($true -eq $includeEmailAction) {
            $EmailActions = [System.Collections.Generic.list[object]]@(
                $ApproveEmailAction
                $ReturnEmailAction
            )

            foreach ($EmailAction in $EmailActions) {
                Write-HidStatus -Message  "Adding Email action to Product" -Event Information
                $null = Add-HIDEmailAction -ProductGUID $selfServiceProduct.selfServiceProductGUID -Body ($EmailAction | ConvertTo-Json)
            }
        }
    }

    foreach ($productToRemove in $ProductToRemoveFromHelloID) {
        $product = $selfServiceProductGrouped[$productToRemove] | Select-Object -First 1
        if ($removeProduct) {
            Write-HidStatus "Removing Product [$($product.name)]" -Event Information
            $null = Remove-HIDSelfServiceProduct -ProductGUID  $product.selfServiceProductGUID
        }
        else {
            Write-HidStatus "Disabling Product [$($product.name)]" -Event Information
            $product.visibility = 'Disabled'
            $disableProductBody = ConvertTo-Json ($product | Select-Object -Property * -ExcludeProperty Code)
            $null = Set-HIDSelfServiceProduct -ProductJson $disableProductBody
        }
    }

    foreach ($productToUpdate in $productExistsInHelloID) {
        $product = $selfServiceProductGrouped[$productToUpdate] | Select-Object -First 1
        if ($true -eq $overwriteExistingProduct) {
            Write-HidStatus "Overwriting existing Product [$($product.name)]" -Event Information

            # Copy existing product
            $overwriteProductBody = [PSCustomObject]@{}
            $product.psobject.properties | ForEach-Object {
                $overwriteProductBody | Add-Member -MemberType $_.MemberType -Name $_.Name -Value $_.Value -Force
            }

            # Optional, set product properties to update (that are in response of get products: https://docs.helloid.com/hc/en-us/articles/115003027353-GET-Get-products)
            $newProduct = $TargetGroupsGrouped[$productToUpdate]
            $overwriteProductBody.name = "$($newProduct.displayName)"
            $overwriteProductBody.Description = "$TargetSystemName - $($newProduct.displayName)"
            $overwriteProductBody.requestCommentOption = $productRequestCommentOption
            $overwriteProductBody.ReturnOnUserDisable = $returnProductOnUserDisable

            # Check if resource owner group is specified and exists, if not create new group
            $resourceOwnerGroupName = if ([string]::IsNullOrWhiteSpace($SAProductResourceOwner) ) { "$($overwriteProductBody.name) Resource Owners" } else { $SAProductResourceOwner }

            $resourceOwnerGroup = Get-HIDGroup -GroupName $resourceOwnerGroupName
            if ($null -eq $resourceOwnerGroup ) {
                Write-HidStatus "Creating a new resource owner group for Product [$($resourceOwnerGroupName)]" -Event Information
                $resourceOwnerGroup = New-HIDGroup -GroupName $resourceOwnerGroupName -isEnabled $true
            }            
            $overwriteProductBody.ManagedByGroupGUID = $($resourceOwnerGroup.groupGuid)

            if ($true -eq $setDistributionGroupOwnerAsResourceOwner) {
                if ($null -eq $newProduct.managedBy) {
                    Write-HidStatus "No owners found of Exchange Distribution Group [$($newProduct.name)]" -Event Information
                }
                else {
                    Write-HidStatus "Setting owners of Exchange Distribution Group [$($newProduct.name)] as members of HelloID Resource Owner Group [$($resourceOwnerGroup.name)]" -Event Information
    
                    $distributionGroupOwners = $newProduct.managedBy
                    foreach ($distributionGroupOwner in $distributionGroupOwners) {
                        # Owners can be either groups or users or a combination of both, therefore, check both
    
                        # Check for user
                        $exchangeUser = $exchangeUsersGrouped[$distributionGroupOwner]
                        if ($null -ne $exchangeUser) {
                            $helloIDUser = $selfServiceUsersGrouped[$($exchangeUser.UserPrincipalName)]
                            if ($null -ne $helloIDUser) {
                                $null = Add-HIDGroupMemberUser -GroupGUID $resourceOwnerGroup.groupGuid -MemberGUID $helloIDUser.userGUID
                            }
                        }
                        else {
                            # Check for group
                            $exchangeGroup = $exchangeGroupsGrouped[$distributionGroupOwner]
                            if ($null -ne $exchangeGroup) {
                                $helloIDGroup = $selfServiceGroupsGrouped[$($exchangeGroup.Name)]
                                if ($null -ne $helloIDGroup) {
                                    $null = Add-HIDGroupMemberGroup -GroupGUID $resourceOwnerGroup.groupGuid -MemberGUID $helloIDGroup.groupGUID
                                }
                            }
                        }
                    }
                }
            }

            # Optional, add product properties to update (that aren't in response of get products: https://docs.helloid.com/hc/en-us/articles/115003027353-GET-Get-products)
            $overwriteProductBody | Add-Member @{
                ApprovalWorkflowName = $SAProductWorkflow
            }

            $overwriteProductBody = ConvertTo-Json -InputObject $overwriteProductBody -depth 10
            $null = Set-HIDSelfServiceProduct -ProductJson $overwriteProductBody

            if ($true -eq $overwriteExistingProductAction) {
                $productActions = $selfServiceProductActionGrouped[$($product.selfServiceProductGUID)]
                foreach ($productAction in $productActions) {
                    $overwritePowerShellAction = $null
                    switch ($productAction.name.tolower()) {
                        'add-groupmembership' {
                            Write-HidStatus "Overwriting existing Product PowerShell Action [$($productAction.name)]" -Event Information
                            $tempAddGroupMembershipAction = $AddGroupMembershipAction.psobject.copy()
                            $overwritePowerShellAction = $tempAddGroupMembershipAction

                            $overwritePowerShellAction.objectGUID = $product.selfServiceProductGUID
                            $overwritePowerShellAction.automationTaskGuid = $productAction.automationTaskGuid
                            $null = Add-HIDPowerShellAction -Body ($overwritePowerShellAction | ConvertTo-Json)
                            break
                        }
                        'remove-groupmembership' {
                            Write-HidStatus "Overwriting existing Product PowerShell Action [$($productAction.name)]" -Event Information
                            $tempRemoveGroupMembershipAction = $RemoveGroupMembershipAction.psobject.copy()
                            $overwritePowerShellAction = $tempRemoveGroupMembershipAction

                            $overwritePowerShellAction.objectGUID = $product.selfServiceProductGUID
                            $overwritePowerShellAction.automationTaskGuid = $productAction.automationTaskGuid
                            $null = Add-HIDPowerShellAction -Body ($overwritePowerShellAction | ConvertTo-Json)
                            break
                        }
                    }
                }
            }

        }
        else {
            # Make sure existing products are enabled
            if ($product.visibility -eq 'Disabled') {
                Write-HidStatus "Enabling existing Product [$($product.name)]" -Event Information
                $product.visibility = $productVisibility
                $product.isEnabled = $true
                $enableProductBody = ConvertTo-Json ($product | Select-Object -Property *)
                $null = Set-HIDSelfServiceProduct -ProductJson $enableProductBody
            }
            Write-HidStatus "No Changes Needed. Product [$($product.name)]" -Event Information
        }
    }

    Write-HidStatus -Message "Successfully synchronized [$TargetSystemName] to HelloID products" -Event Success
    Write-HidSummary -Message "Successfully synchronized [$TargetSystemName] to HelloID products" -Event Success
}
catch {
    Write-HidStatus -Message "Error synchronization of [$TargetSystemName] to HelloID products" -Event Error
    Write-HidStatus -Message "Exception message: $($_.Exception.Message)" -Event Error
    Write-HidStatus -Message "Exception details: $($_.errordetails)" -Event Error
    Write-HidSummary -Message "Error synchronization of [$TargetSystemName] to HelloID products" -Event Failed
}
#endregion
