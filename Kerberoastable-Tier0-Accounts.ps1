<#
Find Kerberoastable Tier-0 accounts and display results in the terminal.
- Kerberoastable = user accounts that have one or more SPNs
- Tier-0 = direct or nested members of the hardcoded Tier-0 groups below
#>

Import-Module ActiveDirectory -ErrorAction Stop

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

# Resolve Tier-0 groups once and keep DN->Name map for quick lookups
$tier0GroupDnToName = @{}
foreach ($groupName in $Tier0Groups) {
  try {
    $group = Get-ADGroup -Identity $groupName -ErrorAction Stop
    $tier0GroupDnToName[$group.DistinguishedName] = $group.Name
  }
  catch {
    Write-Warning "Tier-0 group not found or inaccessible: $groupName"
  }
}

if ($tier0GroupDnToName.Count -eq 0) {
  throw "No Tier-0 groups could be resolved. Verify group names and permissions."
}

# Build full Tier-0 user set (recursive) keyed by user DN
$tier0UsersByDn = @{}
foreach ($groupDn in $tier0GroupDnToName.Keys) {
  try {
    $members = Get-ADGroupMember -Identity $groupDn -Recursive -ErrorAction Stop |
      Where-Object { $_.ObjectClass -eq 'user' }

    foreach ($member in $members) {
      if (-not $tier0UsersByDn.ContainsKey($member.DistinguishedName)) {
        $tier0UsersByDn[$member.DistinguishedName] = $true
      }
    }
  }
  catch {
    Write-Warning "Failed to enumerate members for Tier-0 group DN: $groupDn"
  }
}

# Query all user accounts with SPNs (Kerberoastable candidates)
$spnUsers = Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))' `
  -Properties ServicePrincipalName, Enabled, MemberOf

$results = foreach ($user in $spnUsers) {
  if (-not $tier0UsersByDn.ContainsKey($user.DistinguishedName)) {
    continue
  }

  $directTier0Groups = @()
  foreach ($memberOfDn in @($user.MemberOf)) {
    if ($tier0GroupDnToName.ContainsKey($memberOfDn)) {
      $directTier0Groups += $tier0GroupDnToName[$memberOfDn]
    }
  }

  [PSCustomObject]@{
    SamAccountName    = $user.SamAccountName
    Enabled           = $user.Enabled
    SPNCount          = @($user.ServicePrincipalName).Count
    DirectTier0Groups = ($directTier0Groups | Sort-Object -Unique) -join '; '
    DistinguishedName = $user.DistinguishedName
  }
}

$results = $results | Sort-Object SamAccountName -Unique

if (-not $results) {
  Write-Host "No Kerberoastable Tier-0 user accounts found."
  return
}

Write-Host "Kerberoastable Tier-0 user accounts found: $($results.Count)"
$results |
  Format-Table -AutoSize SamAccountName, Enabled, SPNCount, DirectTier0Groups

# Keep full objects on the pipeline for optional downstream use
$results
