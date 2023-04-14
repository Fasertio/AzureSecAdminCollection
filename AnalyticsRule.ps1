#necessario ps> 6.2
#requires -version 6.2
<#
    .SYNOPSIS
        Estrazione analytics rule ed eventuale attivazione delle stesse selezionando il valore dal CSV
    .DESCRIPTION
        Ha due funzionalità, estrai i template analytics rule su un CSV e seleziona in CSV quali
        analytics rule attivare
    .PARAMETER WorkSpaceName
        Inserire il nome del workspace
    .PARAMETER ResourceGroupName
        Inserire il nome del resource group  
    .NOTES
        AUTHOR: Daniel Simonini
        LASTEDIT: 12/04/23
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$WorkSpaceName,
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    [string]$FileName = "rulestemplate.csv"
)

Function CreazioneAnalyticsRuleDaCSV ($workspaceName, $resourceGroupName, $filename) {
    #Set up the authentication header
    $context = Get-AzContext
    $profile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($profile)
    $token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json' 
        'Authorization' = 'Bearer ' + $token.AccessToken 
    }
    
    $SubscriptionId = $context.Subscription.Id

    #Load all the rule templates so we can copy the information as needed.
    $url = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($ResourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($WorkspaceName)/providers/Microsoft.SecurityInsights/alertruletemplates?api-version=2019-01-01-preview"
    $results = (Invoke-RestMethod -Method "Get" -Uri $url -Headers $authHeader ).value

    #Load the file information

    $fileContents = Import-Csv $FileName -Delimiter ";"

    #Iterate through all the lines in the file
    $fileContents | ForEach-object {
        #Read the selected column (the first column in the file)
        $selected = $_.Selected
        #If this entry has been marked to be used...
        if ($selected.ToUpper() -eq "X") {
            $name = $_.Name
            $kind = $_.Kind
            $displayName = $_.DisplayName
            #Check to see if there is a template that matches the name (there better be!)
            $template = $results | Where-Object { $_.name -eq $name }
            #If we did find a match....
            if ($null -ne $template) {
                $body = ""
                #Depending on the type of alert we are creating, the body has different parameters
                switch ($kind) {
                    "MicrosoftSecurityIncidentCreation" {  
                        $body = @{
                            "kind"       = "MicrosoftSecurityIncidentCreation"
                            "properties" = @{
                                "enabled"       = "true"
                                "productFilter" = $template.properties.productFilter
                                "displayName"   = $template.properties.displayName
                            }
                        }
                    }
                    "Scheduled" {
                        $body = @{
                            "kind"       = "Scheduled"
                            "properties" = @{
                                "enabled"               = "true"
                                "alertRuleTemplateName" = $template.name
                                "displayName"           = $template.properties.displayName
                                "severity"              = $template.properties.severity
                                "tactics"               = $template.properties.tactics
                                "query"                 = $template.properties.query
                                "queryFrequency"        = $template.properties.queryFrequency
                                "queryPeriod"           = $template.properties.queryPeriod
                                "triggerOperator"       = $template.properties.triggerOperator
                                "triggerThreshold"      = $template.properties.triggerThreshold
                                "suppressionDuration"   = "PT5H"  #Azure Sentinel requires a value here 
                                "suppressionEnabled"    = $false
                            }
                        }
                    }
                    "MLBehaviorAnalytics" {
                        if ($template.properties.status -eq "Available") {
                            $body = @{
                                "kind"       = "MLBehaviorAnalytics"
                                "properties" = @{
                                    "enabled"               = "true"
                                    "alertRuleTemplateName" = $template.name
                                }
                            }
                        }
                    }
                    "Fusion" {
                        if ($template.properties.status -eq "Available") {
                            $body = @{
                                "kind"       = "Fusion"
                                "properties" = @{
                                    "enabled"               = "true"
                                    "alertRuleTemplateName" = $template.name
                                }
                            }
                        }
                    }
                    Default { }
                }
                #If we have created the body...
                if ("" -ne $body) {
                    #Create the GUId for the alert and create it.
                    $guid = (New-Guid).Guid
                    #Create the URI we need to create the alert.
                    $uri = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($resourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($workspaceName)/providers/Microsoft.SecurityInsights/alertRules/$($guid)?api-version=2019-01-01-preview"
                    try {
                        Write-Host "Attempting to create rule $($displayName)"
                        $verdict = Invoke-RestMethod -Uri $uri -Method Put -Headers $authHeader -Body ($body | ConvertTo-Json -EnumsAsStrings)
                        Write-Output "Succeeded"
                    }
                    catch {
                        #The most likely error is that there is a missing dataset. There is a new
                        #addition to the REST API to check for the existance of a dataset but
                        #it only checks certain ones.  Hope to modify this to do the check
                        #before trying to create the alert.
                        $errorReturn = $_
                        Write-Error $errorReturn
                    }
                    #This pauses for 5 second so that we don't overload the workspace.
                    Start-Sleep -Seconds 5
                }
            }
        }
    }
}

Function EstrazioneAnalyticsRuleTemplate ($workspaceName, $resourceGroupName, $filename) {

    #Setup the header for the file
    #$output = "Selected,Severity,DisplayName,Kind,Name,Description,Tactics,RequiredDataConnectors,RuleFrequency,RulePeriod,RuleThreshold,Status"
    #$output >> $filename
    
    #Setup the Authentication header needed for the REST calls
    $context = Get-AzContext
    $profile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($profile)
    $token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json' 
        'Authorization' = 'Bearer ' + $token.AccessToken 
    }
    
    $SubscriptionId = (Get-AzContext).Subscription.Id

    #Load the templates so that we can copy the information as needed
    #$url = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($resourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($workspaceName)/providers/Microsoft.SecurityInsights/alertruletemplates?api-version=2020-05-01"
    $url = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($resourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($workspaceName)/providers/Microsoft.SecurityInsights/alertruletemplates?api-version=2019-01-01-preview"
	#echo $url
    $results = (Invoke-RestMethod -Method "Get" -Uri $url -Headers $authHeader ).value

    foreach ($result in $results) {
        #Escape the description field so it does not cause any issues with the CSV file
        #$description = $result.properties.Description
        #Replace any double quotes.  Commas are already taken care of
        #$description = $description -replace '"', '""'

        #Generate the list of data connectors.  Using the pipe as the 
        #delimiter since it does not appear in any data connector name
        $requiredDataConnectors = ""
        foreach ($dc in $result.properties.requiredDataConnectors) {
            $requiredDataConnectors += $dc.connectorId + "|" 
        }
        #If we have an entry, remove the last pipe character
        if ("" -ne $requiredDataConnectors) {
            $requiredDataConnectors = $requiredDataConnectors.Substring(0, $requiredDataConnectors.length - 1)
        }

        #Generate the list of tactics.  Using the pipe as the 
        #delimiter since it does not appear in any data connector name
        $tactics = ""
        foreach ($tactic in $result.properties.tactics) { $tactics += $tactic + "|" }
        #If we have an entry, remove the last pipe character
        if ("" -ne $tactics) {
            $tactics = $tactics.Substring(0, $tactics.length - 1)
        }

        #Translate the query frequency and period text into something a bit more readable.  
        #Handles simple translations only.
        $frequencyText = ConvertISO8601ToText -queryFrequency $result.properties.queryFrequency  -type "Frequency"
        $queryText = ConvertISO8601ToText -queryFrequency $result.properties.queryPeriod -type "Query"

        #Translate the threshold values into some more readable.
        $ruleThresholdText = RuleThresholdText -triggerOperator $result.properties.triggerOperator -triggerThreshold $result.properties.triggerThreshold

        #Create and output the line of information.
		$severity = $result.properties.severity
		$displayName = $result.properties.displayName
		$kind = $result.kind
		$name = $result.Name
		
		[pscustomobject]@{ Selected =" ";Severity=$severity;DisplayName=$displayName;Kind=$kind;Name=$name;Tactics=$tactics;RequiredDataConnectors=$requiredDataConnectors;RuleFrequency=$frequencyText;RulePeriod=$queryText;RuleThreshold=$ruleThresholdText;Status=$result.properties.status }  | Export-Csv $filename -Append -NoTypeInformation
    }
}

function ConvertISO8601ToText($queryFrequency, $type) {
    $returnText = ""
    if ($null -ne $queryFrequency) {
        #Don't need the first character since it will always be a "P"
        $tmp = $queryFrequency.Substring(1, $queryFrequency.length - 1)
        #Check the first character now.  If it is a "T" remove it
        if ($tmp.SubString(0, 1) -eq "T") {
            $tmp = $tmp.Substring(1, $tmp.length - 1)
        }
        #Get the last character to determine if we are dealing with minutes, hours, or days, and then strip it out
        $timeDesignation = $tmp.Substring($tmp.length - 1)
        $timeLength = $tmp.Substring(0, $tmp.length - 1)

        $returnText = "Every " + $timeLength
        if ($type -eq "Query") {
            $returnText = "Last " + $timeLength
        }
        switch ($timeDesignation) {
            "M" {
                $returnText += " minute"
                if ([int]$timeLength -gt 1) { $returnText += "s" }
            }
            "H" {
                $returnText += " hour" 
                if ([int]$timeLength -gt 1) { $returnText += "s" }
            }
            "D" {
                $returnText += " day" 
                if ([int]$timeLength -gt 1) { $returnText += "s" }
            }
            Default { }
        }
    }
    return $returnText
}

Function RuleThresholdText($triggerOperator, $triggerThreshold) {
    $returnText = ""
    if ($null -ne $triggerOperator) {
        $returnText = "Trigger alert if query returns "

        switch ($triggerOperator) {
            "GreaterThan" {
                $returnText += "more than"
                
            }
            "FewerThan" {
                $returnText += "less than" 
                
            }
            "EqualTo" {
                $returnText += "exactly" 
                
            }
            "NotEqualTo" {
                $returnText += "different than" 
                
            }
            Default { }
        }
        $returnText += " " + $triggerThreshold + " results"
    }
    return $returnText
}

#Estrazione analytics rule create
Function ActualAnalyticsRule($WorkSpaceName,$ResourceGroupName){
    $output = Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -workspaceName $WorkSpaceName
    $output | ForEach-Object{
        $o = [PSCustomObject]@{
            'AlertDetailOverrideAlertDescriptionFormat' = $_.AlertDetailOverrideAlertDescriptionFormat
            'AlertDetailOverrideAlertDisplayNameFormat' = $_.AlertDetailOverrideAlertDisplayNameFormat
            'AlertDetailOverrideAlertSeverityColumnName' = $_.AlertDetailOverrideAlertSeverityColumnName
            'AlertDetailOverrideAlertTacticsColumnName' = $_.AlertDetailOverrideAlertTacticsColumnName
            'AlertRuleTemplateName' = $_.AlertRuleTemplateName
            'DisplayName' = $_.DisplayName
            'Enabled' = $_.Enabled
            'GroupingConfigurationEnabled' = $_.GroupingConfigurationEnabled
            'GroupingConfigurationGroupByAlertDetail' = $_.GroupingConfigurationGroupByAlertDetail
            'GroupingConfigurationGroupByCustomDetail' = $_.GroupingConfigurationGroupByCustomDetail
            'GroupingConfigurationGroupByEntity' = $_.GroupingConfigurationGroupByEntity
            'GroupingConfigurationReopenClosedIncident' = $_.GroupingConfigurationReopenClosedIncident
            'IncidentConfigurationCreateIncident' = $_.IncidentConfigurationCreateIncident
            'Kind' = $_.Kind
            'Name' = $_.Name
            'Severity' = $_.Severity
            'SystemDataCreatedBy' = $_.SystemDataCreatedBy
            'SystemDataLastModifiedAt' = $_.SystemDataLastModifiedAt
            'SystemDataLastModifiedBy' = $_.SystemDataLastModifiedBy
            'Tactic' = $_.Tactic
            'TemplateVersion' = $_.TemplateVersion
        }

        $o | Export-Csv -Path "./test.csv" -Append
    }
}

#Execute the code
if (! $Filename.EndsWith(".csv")) {
    $FileName += ".csv"
}


Function Menu(){
    Clear-Host
    Write-Host "=================== Analytics rule ================="
    Write-Host "Workspace: $WorkspaceName"
    Write-Host "Resource Group: $ResourceGroupName"
    Write-Host "===================================================="
    Write-Host "1: Estrazione analytics rule attive"
    Write-Host "2: Estrazione template analytics rule"
    Write-Host "3: Attivazione Analytics rule tramite il template"
    Write-Host "q: Esci"
}

do{
    Menu
    $UserInput = Read-Host "> "
    switch($UserInput){
        '1' {ActualAnalyticsRule $WorkSpaceName $ResourceGroupName}
        '2' {EstrazioneAnalyticsRuleTemplate $WorkSpaceName $ResourceGroupName $FileName}
        '3' {CreazioneAnalyticsRuleDaCSV $WorkSpaceName $ResourceGroupName $FileName}
    }
    pause
}until($UserInput -eq "q")


