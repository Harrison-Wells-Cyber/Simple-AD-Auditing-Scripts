<#
Tier-0 group membership export (PowerShell 5.1)
- CSV output (OVERWRITES)
- Recursive membership enumeration
- Outputs USERS and COMPUTERS only
- Run this as a scheduled task to maintain an up to date list of tier 0 objects
#>

# ----------------------------
# Hardcoded output location + file
# ----------------------------
$OutputDir = "\\FILESERVER\Share\Tier0Exports"   # <-- CHANGE THIS
$CsvPath   = Join-Path $OutputDir "Tier0_Members.csv"

# ----------------------------
# Hardcoded Tier-0 group list
# Your organization may have custom tier 0 groups
# Discover them with Semperis Forest Druid and add them here
# ----------------------------
$Tier0Groups = @(
  "Exchange Servers",
  "Print Operators",
  "Schema Admins",
  "Performance Log Users",
  "Administrators",
  "Exchange Domain Servers",
  "Remote Desktop Users",
  "Group Policy Creator Owners",
  "Enterprise Read-only Domain Controllers",
  "Incoming Forest Trust Builders",
  "Server Operators",
  "Exchange Enterprise Servers",
  "Enterprise Key Admins",
  "Organization Management",
  "Exchange Windows Permissions",
  "Enterprise Admins",
  "Backup Operators",
  "Domain Controllers",
  "DnsAdmins",
  "Exchange Trusted Subsystem",
  "Account Operators",
  "Domain Admins",
  "Key Admins",
  "Read-only Domain Controllers",
  "Cert Publishers",
  "Distributed COM Users",
  "Exchange Install Domain Servers"
)

# ----------------------------
# Prereqs
# ----------------------------
Import-Module ActiveDirectory -ErrorAction Stop

if (-not (Test-Path $OutputDir)) {
  New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

# ----------------------------
# Cache for user/computer lookups (DN -> details)
# ----------------------------
$principalCache = @{}

function Get-UserDetails {
  param([Parameter(Mandatory)][string]$DistinguishedName)

  $u = Get-ADUser -Identity $DistinguishedName -Properties `
    SamAccountName,Enabled,SID,WhenCreated,LastLogonDate,PasswordLastSet,`
    UserPrincipalName,DisplayName,Mail,Department,Title,Manager `
    -ErrorAction Stop

  return [pscustomobject]@{
    ObjectClass       = "user"
    Name              = $u.Name
    DisplayName       = $u.DisplayName
    SamAccountName    = $u.SamAccountName
    UPN               = $u.UserPrincipalName
    Enabled           = $u.Enabled
    SID               = $u.SID.Value
    Mail              = $u.Mail
    Department        = $u.Department
    Title             = $u.Title
    Manager           = $u.Manager
    WhenCreated       = $u.WhenCreated
    LastLogonDate     = $u.LastLogonDate
    PasswordLastSet   = $u.PasswordLastSet
    DistinguishedName = $u.DistinguishedName

    DNSHostName       = $null
    OperatingSystem   = $null
    OSVersion         = $null
  }
}

function Get-ComputerDetails {
  param([Parameter(Mandatory)][string]$DistinguishedName)

  $c = Get-ADComputer -Identity $DistinguishedName -Properties `
    SamAccountName,Enabled,SID,WhenCreated,LastLogonDate,PasswordLastSet,`
    DNSHostName,OperatingSystem,OperatingSystemVersion `
    -ErrorAction Stop

  return [pscustomobject]@{
    ObjectClass       = "computer"
    Name              = $c.Name
    DisplayName       = $null
    SamAccountName    = $c.SamAccountName
    UPN               = $null
    Enabled           = $c.Enabled
    SID               = $c.SID.Value
    Mail              = $null
    Department        = $null
    Title             = $null
    Manager           = $null
    WhenCreated       = $c.WhenCreated
    LastLogonDate     = $c.LastLogonDate
    PasswordLastSet   = $c.PasswordLastSet
    DistinguishedName = $c.DistinguishedName

    DNSHostName       = $c.DNSHostName
    OperatingSystem   = $c.OperatingSystem
    OSVersion         = $c.OperatingSystemVersion
  }
}

# ----------------------------
# Main: enumerate groups -> members
# ----------------------------
$rows = New-Object System.Collections.Generic.List[object]

foreach ($groupName in $Tier0Groups) {

  $group = $null
  try {
    $group = Get-ADGroup -Identity $groupName -ErrorAction Stop
  } catch {
    continue
  }

  $members = @()
  try {
    $members = Get-ADGroupMember -Identity $group.DistinguishedName -Recursive -ErrorAction Stop
  } catch {
    continue
  }

  foreach ($m in $members) {

    # Only users and computers in output
    if ($m.ObjectClass -ne "user" -and $m.ObjectClass -ne "computer") {
      continue
    }

    # Cache details by DN
    if (-not $principalCache.ContainsKey($m.DistinguishedName)) {
      try {
        if ($m.ObjectClass -eq "user") {
          $principalCache[$m.DistinguishedName] = Get-UserDetails -DistinguishedName $m.DistinguishedName
        } else {
          $principalCache[$m.DistinguishedName] = Get-ComputerDetails -DistinguishedName $m.DistinguishedName
        }
      } catch {
        $principalCache[$m.DistinguishedName] = $null
      }
    }

    $p = $principalCache[$m.DistinguishedName]
    if ($null -eq $p) { continue }

    # PS 5.1-safe display name fallback
    $memberName = $p.Name
    if ($p.ObjectClass -eq "user" -and -not [string]::IsNullOrWhiteSpace($p.DisplayName)) {
      $memberName = $p.DisplayName
    }

    # One row per group-member pair
    $rows.Add([pscustomobject]@{
      Tier0Group           = $groupName
      Tier0GroupDN         = $group.DistinguishedName

      MemberObjectClass    = $p.ObjectClass
      MemberName           = $memberName
      SamAccountName       = $p.SamAccountName
      UserPrincipalName    = $p.UPN
      Enabled              = $p.Enabled
      SID                  = $p.SID
      Mail                 = $p.Mail
      Department           = $p.Department
      Title                = $p.Title
      Manager              = $p.Manager

      WhenCreated          = $p.WhenCreated
      LastLogonDate        = $p.LastLogonDate
      PasswordLastSet      = $p.PasswordLastSet

      DNSHostName          = $p.DNSHostName
      OperatingSystem      = $p.OperatingSystem
      OSVersion            = $p.OSVersion

      MemberDistinguishedName = $p.DistinguishedName
    })
  }
}

# ----------------------------
# Export CSV (OVERWRITES PREVIOUS OUTPUT)
# ----------------------------
$rows |
  Sort-Object Tier0Group, MemberObjectClass, SamAccountName, MemberDistinguishedName |
  Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -Force
