using namespace Microsoft.PowerShell.Commands
using namespace System.Management.Automation

function Invoke-TravisAPIRequest {
    [CmdletBinding(SupportsPaging)]
    param(
        [WebRequestMethod] $Method = [WebRequestMethod]::Get,

        [Parameter(Mandatory, Position = 0)]
        [string] $Path,

        $Body,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Security.SecureString] $Token
    )
    $uri = [Uri]::new([Uri]::new('https://api.travis-ci.org/'), $Path)
    $decodedToken = [PSCredential]::new('dummy', $Token).GetNetworkCredential().Password
    $header = @{
        "Travis-API-Version" = "3"
        "Authorization"      = "token $decodedToken"
        "User-Agent"         = "PowerShell"
    }
    if ($Method -ne [WebRequestMethod]::Get) {
        $Body = $Body | ConvertTo-Json
    }
    $query = [Web.HttpUtility]::ParseQueryString($uri.Query)
    if ($PSBoundParameters.ContainsKey('First')) {
        $query['limit'] = $PSCmdlet.PagingParameters.First
    }
    if ($PSBoundParameters.ContainsKey('Skip')) {
        $query['offset'] = $PSCmdlet.PagingParameters.Skip
    }
    if ($query.ToString()) {
        $uri = [Uri]::new($uri, '?' + $query.ToString())
    }
    $result = Invoke-RestMethod -Method $Method -Uri $uri -Header $header -ContentType 'application/json' -Body $Body
    if ($PSCmdlet.PagingParameters.IncludeTotalCount) {
        $PSCmdlet.PagingParameters.NewTotalCount($result.'@pagination'.count, 1)
    }
    $result
}

function Get-TravisRepository {
    [CmdletBinding(SupportsPaging)]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('login')]
        [string] $Owner = (Get-TravisUser -Token $Token).login,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Security.SecureString] $Token
    )
    process {
        $PSBoundParameters.Remove('Owner') | Out-Null

        (Invoke-TravisAPIRequest -Path "/owner/$Owner/repos" @PSBoundParameters).repositories
    }
}

function Get-TravisCruiseControlFeedUrl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, Position = 0)]
        [string] $Slug
    )
    process {
        "https://api.travis-ci.org/repositories/$Slug/cc.xml"
    }
}

function Get-TravisUser {
    [CmdletBinding()]
    param(
        [Parameter()]
        [int] $Id,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Security.SecureString] $Token
    )
    $path = if ($id) {
        "user/$id"
    } else {
        "user"
    }
    Invoke-TravisAPIRequest -Path $path -Token $Token
}

function Start-TravisRepositorySync {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('id')]
        [int] $UserId = (Get-TravisUser -Token $Token).id,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Security.SecureString] $Token
    )
    process {
        Invoke-TravisAPIRequest -Method POST "user/$UserId/sync" -Token $Token
    }
}

function Sync-TravisRepositories {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('id')]
        [int] $UserId = (Get-TravisUser -Token $Token).id,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Security.SecureString] $Token
    )
    Start-TravisRepositorySync -UserId $UserId -Token $Token | Out-Null
    Wait-TravisRepositorySync -UserId $UserId -Token $Token
}

function Wait-TravisRepositorySync {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('id')]
        [int] $UserId = (Get-TravisUser -Token $Token).id,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Security.SecureString] $Token
    )

    while ((Get-TravisUser -Id $UserId -Token $Token).is_syncing) {
        Write-Information "Travis repositories are syncing"
        Start-Sleep 1
    }
    Write-Information "Sync completed"
}

function Enable-TravisRepository {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(ValueFromPipelineByPropertyName, Position = 0, Mandatory)]
        [string] $Slug,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Security.SecureString] $Token
    )

    process {
        if ($PSCmdlet.ShouldProcess("Enabling Travis Repository `"$Slug`"", "Enable Travis repository `"$Slug`"?", "Confirm")) {
            Invoke-TravisAPIRequest -Method POST "/repo/$([Uri]::EscapeDataString($Slug))/activate" -Token $Token
        }
    }
}

function Add-TravisEnvironmentVariable {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(ValueFromPipelineByPropertyName, Position = 0, Mandatory)]
        [string] $Slug,

        [Parameter(Mandatory, Position = 1)]
        [string] $Name,
        [Parameter(Mandatory, Position = 2)]
        [string] $Value,
        [Parameter()]
        [switch] $Public,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Security.SecureString] $Token
    )
    process {
        if ($PSCmdlet.ShouldProcess("Enabling Travis Repository `"$Slug`"", "Enable Travis repository `"$Slug`"?", "Confirm")) {
            Invoke-TravisAPIRequest -Method POST "/repo/$([Uri]::EscapeDataString($Slug))/env_vars" -Token $Token -Body @{
                'env_var.name'   = $Name
                'env_var.value'  = $value
                'env_var.public' = [bool]$Public
            }
        }
    }
}
