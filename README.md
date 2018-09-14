# Travis for PowerShell <img src="https://travis-ci.com/images/logos/TravisCI-Mascot-1.png" height="90" align="left">

[![powershellgallery](https://img.shields.io/powershellgallery/v/PSTravis.svg)](https://www.powershellgallery.com/packages/PSTravis)
[![downloads](https://img.shields.io/powershellgallery/dt/PSTravis.svg)](https://www.powershellgallery.com/packages/PSTravis)

Module to interact with the [Travis API](https://developer.travis-ci.com/) from PowerShell.


## Installation

```powershell
Install-Module PSTravis
```

## Included

- `Get-TravisUser`
- `Get-TravisRepository`
- `Get-TravisCruiseControlFeedUrl`
- `Enable-TravisRepository`
- `Add-TravisEnvironmentVariable`
- `Get-TravisEnvironmentVariable`
- `Update-TravisEnvironmentVariable`
- `Remove-TravisEnvironmentVariable`
- `Sync-TravisRepositories`
- `Start-TravisRepositorySync`
- `Wait-TravisRepositorySync`

Missing something? PRs welcome!

## Authentication

To access private repositories and make changes, provide an API token.
This token can be provided to all PSGitHub functions as a `SecureString` through the `-Token` parameter.
You can set a default token to be used by changing `$PSDefaultParameterValues` in your `profile.ps1`:

### On Windows

```powershell
$PSDefaultParameterValues['*Travis*:Token'] = 'YOUR_ENCRYPTED_TOKEN' | ConvertTo-SecureString
```

To get the value for `YOUR_ENCRYPTED_TOKEN`, run `Read-Host -AsSecureString | ConvertFrom-SecureString` once and paste in your token.

### On macOS/Linux

macOS and Linux do not have access to the Windows Data Protection API, so they cannot use `ConvertFrom-SecureString`
to generate an encrypted plaintext version of the token without a custom encryption key.

If you are not concerned about storing the token in plain text in the `profile.ps1`, you can set it like this:

```powershell
$PSDefaultParameterValues['*Travis*:Token'] = 'YOUR_PLAINTEXT_TOKEN' | ConvertTo-SecureString -AsPlainText -Force
```

Alternatively, you could store the token in a password manager or the Keychain, then retrieve it in your profile and set it the same way.
