# Input bindings are passed in via param block.
param($Timer)

# Get the current universal time in the default string format.
$currentUTCtime = (Get-Date).ToUniversalTime()

# The 'IsPastDue' property is 'true' when the current function invocation is later than scheduled.
if ($Timer.IsPastDue) {
    Write-Host "PowerShell timer is running late!"
}


 $checkPointFile = ".\QualysKBCheckpoint.csv"
 $endTime = [datetime]::UtcNow
 $customerId = $env:workspaceId
 $sharedKey = $env:workspacekey
 $username = $env:apiUsername
 $password = $env:apiPassword
 $tablename = "QualysKB"
 $timeInterval = $env:timeInterval
 $filterparameters = $env:filterParameters
 $Uri = $env:Uri
     


function Html-ToText {
 param([System.String] $html)

 # remove line breaks, replace with spaces
 $html = $html -replace "(`r|`n|`t)", " "
 # write-verbose "removed line breaks: `n`n$html`n"

 # remove invisible content
 @('head', 'style', 'script', 'object', 'embed', 'applet', 'noframes', 'noscript', 'noembed') | % {
  $html = $html -replace "<$_[^>]*?>.*?</$_>", ""
 }
 # write-verbose "removed invisible blocks: `n`n$html`n"

 # Condense extra whitespace
 $html = $html -replace "( )+", " "
 # write-verbose "condensed whitespace: `n`n$html`n"

 # Add line breaks
 @('div','p','blockquote','h[1-9]') | % { $html = $html -replace "</?$_[^>]*?>.*?</$_>", ("`n" + '$0' )} 
 # Add line breaks for self-closing tags
 @('div','p','blockquote','h[1-9]','br') | % { $html = $html -replace "<$_[^>]*?/>", ('$0' + "`n")} 
 # write-verbose "added line breaks: `n`n$html`n"

 #strip tags 
 $html = $html -replace "<[^>]*?>", ""
 # write-verbose "removed tags: `n`n$html`n"
  
 # replace common entities
 @( 
  @("&amp;bull;", " * "),
  @("&amp;lsaquo;", "<"),
  @("&amp;rsaquo;", ">"),
  @("&amp;(rsquo|lsquo);", "'"),
  @("&amp;(quot|ldquo|rdquo);", '"'),
  @("&amp;trade;", "(tm)"),
  @("&amp;frasl;", "/"),
  @("&amp;(quot|#34|#034|#x22);", '"'),
  @('&amp;(amp|#38|#038|#x26);', "&amp;"),
  @("&amp;(lt|#60|#060|#x3c);", "<"),
  @("&amp;(gt|#62|#062|#x3e);", ">"),
  @('&amp;(copy|#169);', "(c)"),
  @("&amp;(reg|#174);", "(r)"),
  @("&amp;nbsp;", " "),
  @("&amp;(.{2,6});", "")
 ) | % { $html = $html -replace $_[0], $_[1] }
 # write-verbose "replaced entities: `n`n$html`n"

 return $html

}
 # Function to retrieve the checkpoint start time of the last successful API call for a given logtype. Checkpoint file will be created if none exists
function GetStartTime($CheckpointFile, $timeInterval){
   
    $firstStartTimeRecord = [datetime]::UtcNow.AddHours(-$timeInterval)
    
    if ([System.IO.File]::Exists($CheckpointFile) -eq $false) {
        $CheckpointLog = @{}
        $CheckpointLog.Add('LastSuccessfulTime',$firstStartTimeRecord.ToString("yyyy-MM-ddTHH:mm:ssZ"))        
        $CheckpointLog.GetEnumerator() | Select-Object -Property Key,Value | Export-CSV -Path $CheckpointFile -NoTypeInformation
        return $firstStartTimeRecord 
    }
    else{
        $GetLastRecordTime = Import-Csv -Path $CheckpointFile
        $startTime = $GetLastRecordTime | ForEach-Object{ 
                        if($_.Key -eq 'LastSuccessfulTime'){
                            $_.Value
                        }
                    }
        return $startTime
    }
}


# Function to update the checkpoint time with the last successful API call end time
function UpdateCheckpointTime($CheckpointFile, $LastSuccessfulTime){
    $checkpoints = Import-Csv -Path $CheckpointFile
    $checkpoints | ForEach-Object{ if($_.Key -eq 'LastSuccessfulTime'){$_.Value = $LastSuccessfulTime.ToString("yyyy-MM-ddTHH:mm:ssZ")}}
    $checkpoints | Select-Object -Property Key,Value | Export-CSV -Path $CheckpointFile -NoTypeInformation
}


function QualysKB {

    $startDate = GetStartTime -CheckpointFile $checkPointFile  -timeInterval $timeInterval
    $hdrs = @{"X-Requested-With"="powershell"}  
    $base = "$Uri"
    $body = "action=login&username=$username&password=$password"  
    Invoke-RestMethod -Headers $hdrs -Uri "$base/session/" -Method Post -Body $body -SessionVariable sess  

    # Invoke the API Request and assign the response to a variable ($response)
    $response = (Invoke-RestMethod -Headers $hdrs -Uri "$base/knowledge_base/vuln/?action=list&published_after=$($startDate)$filterparameters" -WebSession $sess) 


    # Iterate through each vulnerability recieved from the API call and assign the variables (Column Names in LA) to each XML variable and place each vulnerability as an object in the $objs array.
        $objs = @()  
        0 .. $response.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN.Length | ForEach-Object {  
          $obj = New-Object PSObject  
          if($response.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN[$_].QID -eq $null) {     # if the vuln ID is mull which will mean the entry is null, this occurs on the last entry of the response. Should only occur once.
            Write-Host ("A null line was excluded") 
          }
          else {
          Add-Member -InputObject $obj -MemberType NoteProperty -Name ID -Value $response.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN[$_].QID  
          Add-Member -InputObject $obj -MemberType NoteProperty -Name Title -Value $response.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN[$_].TITLE."#cdata-section"
          Add-Member -InputObject $obj -MemberType NoteProperty -Name Category -Value $response.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN[$_].CATEGORY
          Add-Member -InputObject $obj -MemberType NoteProperty -Name Consequence -Value $response.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN[$_].CONSEQUENCE."#cdata-section"
          $Diagnosisconverted = Html-ToText($response.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN[$_].DIAGNOSIS."#cdata-section")
          Add-Member -InputObject $obj -MemberType NoteProperty -Name Diagnosis -Value $Diagnosisconverted
          Add-Member -InputObject $obj -MemberType NoteProperty -Name Last_Service_Modification_DateTime -Value $response.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN[$_].LAST_SERVICE_MODIFICATION_DATETIME
          Add-Member -InputObject $obj -MemberType NoteProperty -Name Patchable -Value $response.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN[$_].PATCHABLE
          Add-Member -InputObject $obj -MemberType NoteProperty -Name CVE_ID -Value $response.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN[$_].CVE_LIST.CVE.ID."#cdata-section"
          Add-Member -InputObject $obj -MemberType NoteProperty -Name CVE_URL -Value $response.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN[$_].CVE_LIST.CVE.URL."#cdata-section"
          Add-Member -InputObject $obj -MemberType NoteProperty -Name Vendor_Reference_ID -Value $response.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN[$_].VENDOR_REFERENCE_LIST.VENDOR_REFERENCE.ID."#cdata-section"
          Add-Member -InputObject $obj -MemberType NoteProperty -Name Vendor_Reference_URL -Value $response.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN[$_].VENDOR_REFERENCE_LIST.VENDOR_REFERENCE.URL."#cdata-section"
          Add-Member -InputObject $obj -MemberType NoteProperty -Name PCI_Flag -Value $response.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN[$_].PCI_FLAG
          Add-Member -InputObject $obj -MemberType NoteProperty -Name Published_DateTime -Value $response.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN[$_].PUBLISHED_DATETIME
          Add-Member -InputObject $obj -MemberType NoteProperty -Name Severity_Level -Value $response.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN[$_].SEVERITY_LEVEL
          Add-Member -InputObject $obj -MemberType NoteProperty -Name Software_Product -Value $response.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN[$_].SOFTWARE_LIST.SOFTWARE.PRODUCT."#cdata-section"
          Add-Member -InputObject $obj -MemberType NoteProperty -Name Software_Vendor -Value $response.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN[$_].SOFTWARE_LIST.SOFTWARE.VENDOR."#cdata-section"
          $Solutionconverted = Html-ToText($response.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN[$_].SOLUTION."#cdata-section")
          Add-Member -InputObject $obj -MemberType NoteProperty -Name Solution -Value $Solutionconverted
          Add-Member -InputObject $obj -MemberType NoteProperty -Name Vuln_Type -Value $response.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN[$_].VULN_TYPE
          Add-Member -InputObject $obj -MemberType NoteProperty -Name Discovery_Additional_Info -Value $response.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN[$_].DISCOVERY.ADDITIONAL_INFO
          Add-Member -InputObject $obj -MemberType NoteProperty -Name Discovery_Auth_Type -Value $response.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN[$_].DISCOVERY.AUTH_TYPE_LIST.AUTH_TYPE
          Add-Member -InputObject $obj -MemberType NoteProperty -Name Discovery_Remote -Value $response.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN[$_].DISCOVERY.REMOTE
          $objs += $obj  


            }
        }
   
# Logout of the Session
    Invoke-RestMethod -Headers $hdrs -Uri "$base/session/" -Method Post -Body "action=logout" -WebSession $sess    


# Iterate through each vulnerabilty obj in the $objs array, covert it to JSON and POST it to the Log Analytics API individually        
    if ($objs.Length -ne 0){
        $jsonPayload = $objs | ConvertTo-Json
        $mbytes = ([System.Text.Encoding]::UTF8.GetBytes($objs)).Count/1024/1024          
        # Check the payload size, if under 30MB post to Log Analytics.
        if (($mbytes -le 30)){             
                   
            $responseCode = Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($jsonPayload)) -logType $tablename 
              
            if ($responseCode -ne 200){
                Write-Host "ERROR: Log Analytics POST, Status Code: $responseCode, unsuccessful."
            } 
            else {
                Write-Host "SUCCESS: Total Qualys events posted to Log Analytics: $mbytes MB" -ForegroundColor Green
                UpdateCheckpointTime -CheckpointFile $checkPointFile -LastSuccessfulTime $endTime    
            }
            
        }
        else {
            Write-Host "ERROR: Log Analytics POST failed due to paylog exceeding 30Mb: $mbytes"
            }
        }
        else {
           Write-Output  ([DateTime]$startDate)
           $startInterval = $startDate
           $endInterval = $endTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
           Write-Host "INFO: No new Qualys Vulnaribilites discovered between $startInterval and $endInterval"
         
           
        }
 }




# Function to build the authorization signature to post to Log Analytics
function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date;
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource;
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash);
    $keyBytes = [Convert]::FromBase64String($sharedKey);
    $sha256 = New-Object System.Security.Cryptography.HMACSHA256;
    $sha256.Key = $keyBytes;
    $calculatedHash = $sha256.ComputeHash($bytesToHash);
    $encodedHash = [Convert]::ToBase64String($calculatedHash);
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash;
    return $authorization;
}

# Function to POST the data payload to a Log Analytics workspace 
function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $TimeStampField = "DateValue"
    $method = "POST";
    $contentType = "application/json";
    $resource = "/api/logs";
    $rfc1123date = [DateTime]::UtcNow.ToString("r");
    $contentLength = $body.Length;
    $signature = Build-Signature -customerId $customerId -sharedKey $sharedKey -date $rfc1123date -contentLength $contentLength -method $method -contentType $contentType -resource $resource;
    $uri = "https://$($customerId).ods.opinsights.azure.com$($resource)?api-version=2016-04-01";
    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    };
    $response = Invoke-WebRequest -Body $body -Uri $uri -Method $method -ContentType $contentType -Headers $headers -UseBasicParsing
    return $response.StatusCode
}



QualysKB



# Write an information log with the current time.
Write-Host "PowerShell timer trigger function ran! TIME: $currentUTCtime"
