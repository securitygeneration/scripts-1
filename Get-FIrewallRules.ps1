Function Get-FirewallRules {

param(
    #profile
    [Parameter(Mandatory=$false,Position=0,ValueFromPipeLine=$false)]
    [ValidateSet("Domain","Public","Private","All")] 
    [string]$profile = "All",

    #direction
    [Parameter(Mandatory=$false,Position=1,ValueFromPipeLine=$false)]
    [ValidateSet("Inbound","Outbound","All")] 
    [string]$direction = "All",

    #state
    [Parameter(Mandatory=$false,Position=2,ValueFromPipeLine=$false)]
    [ValidateSet("Enabled","Disabled","All")] 
    [string]$state = "All",

    #protocol
    [Parameter(Mandatory=$false,Position=3,ValueFromPipeLine=$false)]
    [ValidateSet("TCP","UDP","ICMPv4","ICMPv6","IGMP","GRE")] # IGMP = 2, GRE = 47
    [string]$protocol = "All",

    #action
    [Parameter(Mandatory=$false,Position=4,ValueFromPipeLine=$false)]
    [ValidateSet("Allow","Block","NotConfigured","All")] 
    [string]$action = "All",

    #local port number
    [Parameter(Mandatory=$false,Position=5,ValueFromPipeLine=$false)]
    [ValidateRange(0,65535)] 
    [int]$lPort,

    #remote port number
    [Parameter(Mandatory=$false,Position=6,ValueFromPipeLine=$false)]
    [ValidateRange(0,65535)] 
    [int]$rPort,

    [Parameter(Mandatory=$false,Position=7,ValueFromPipeLine=$false)]
    [ValidateNotNullorEmpty()] 
    [string]$program
)

    Import-Module NetSecurity

    #get initial rule set
    $rules = @(Get-NetFirewallRule -All)

    #filter on action
    switch ($action) {
        "All" {$rules = $rules}
        default {$rules = $rules.Where({$_.Action -eq $action})}
    }

    #filter on direction
    switch ($direction) {
        "All" {$rules = $rules}
        default {$rules = $rules.Where({$_.Direction -eq $direction})}
    }

    #filter on state
    switch ($state) {
        "All" {$rules = $rules}
        "Enabled" {$rules = $rules.Where({$_.Enabled -eq "True"})}
        "Disabled" {$rules = $rules.Where({$_.Enabled -eq "False"})}
    }
  
    #fix protocol mapping for IGMP and GRE
    if ($protocol = "IGMP") {$protocol = "2"}
    if ($protocol = "GRE") {$protocol = "47"}

    #filter on protocol
    #TODO: Add rest of protocols that are supported (some kind of dictionary to map name to number)
    switch ($protocol) {
        "All" {$rules = $rules}
        default {$rules = @($rules.ForEach({@(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).Where({($_.Protocol -eq $protocol) -or ($_.Protocol -eq "Any")}) })).ForEach({Get-NetFirewallRule -AssociatedNetFirewallPortFilter $_})}
    }

    #fiter on action
    switch ($action) {
        "All" {$rules = $rules}
        default {$rules = $rules.Where({$_.Action -eq $action})}
    }

    #filter on profile
    switch ($profile) {
        "All" {$rules = $rules}
        default {$rules = $rules.Where({($_.Profile -like "*$profile*") -or ($_.Profile -eq "Any")})}
    }

    #filter on port number
    #TODO: Work out how to find port in range x-y
    if ($lPort) {
       $rules = @($rules.ForEach({@(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).Where({($_.LocalPort -eq $lPort) -or ($_.LocalPort -contains $lPort) -or ($_.LocalPort -eq "Any")}) })).ForEach({Get-NetFirewallRule -AssociatedNetFirewallPortFilter $_})
    }

    if ($rPort) {
        $rules = @($rules.ForEach({@(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).Where({($_.RemotePort -eq $rPort) -or ($_.RemotePort -contains $rPort) -or ($_.RemotePort -eq "Any")}) })).ForEach({Get-NetFirewallRule -AssociatedNetFirewallPortFilter $_})
    }

    #filter on process
    #TODO: check this works for services too
    if ($program) {
        $rules = @($rules.ForEach({@(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $_).Where({($_.Program -eq $program) -or ($_.Program -eq "Any")})})).ForEach({Get-NetFirewallRule -AssociatedNetFirewallApplicationFilter $_})
    }

    #get default actions for profiles
    $profileStates = Get-NetFirewallProfile
    Write-Host "Default Profile States:"
    $profileStates.ForEach({Write-Host "`t$($_.Name)`tInbound:$($_.DefaultInboundAction) || Outbound:$($_.DefaultOutboundAction)"})

    #return matching rules
    #TODO: return rules in some sensible way, group by direction/state etc?
}
