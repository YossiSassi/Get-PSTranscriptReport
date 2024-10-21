####   Get-PSTranscriptReport   ####
# PowerShell Transcripts Analysis & Report (analyzing PSTranscriptions folder)
# Comments to yossis@protonmail.com
# v0.93 - work in progress
# To be added -> consider basic suspicious/malicious detections (suspicious keywords match + Encoded commands/Base64) + other improvements to code + detailed help

param (
    [cmdletbinding()]    
    [string]$Jsonfile = [System.String]::Empty,
    [switch]$OpenResultsInGridView
)

# Set error action preference to not display non-terminating errors
$EAP = $ErrorActionPreference;
$ErrorActionPreference = "silentlycontinue";

# Check if a json file with the parameters was specified, and if so - use it
if ($Jsonfile -ne [System.String]::Empty) {
    if (Test-Path $Jsonfile -eq $false) {
        Write-Warning "[!] cannot find file $Jsonfile. make sure the filePath is correct and try again.";
        break
    }

    Write-Host "[!] json file specified. using parameters from $Jsonfile.";
    $PSTranscriptsParameters = Get-Content $Jsonfile -Raw | ConvertFrom-Json;
    $TranscriptFolder = $PSTranscriptsParameters.PSTranscriptsParameters.TranscriptFolder;
    $StartDateInput = $PSTranscriptsParameters.PSTranscriptsParameters.StartDateInput;
    $EndDateInput = $PSTranscriptsParameters.PSTranscriptsParameters.EndDateInput;

    Write-Host "Transcripts folder -> $($TranscriptFolder.ToUpper())" -ForegroundColor Cyan;
    $Dateformat = "ddMMyyyy";
    $StartDate = [datetime]::ParseExact($StartDateInput, $Dateformat, $null);
    Write-Host "StartDate -> $($StartDate.DateTime)" -ForegroundColor Cyan;
    $EndDate = [datetime]::ParseExact($EndDateInput, $Dateformat, $null);
    Write-Host "EndDate -> $($EndDate.DateTime)" -ForegroundColor Cyan
}

else { # get parameters from user input
# Set transcripts folder path
$TranscriptFolder = Read-Host "Type the transcripts folder (e.g. C:\PSTranscripts), or press <Enter> for current folder";

if ($TranscriptFolder -eq "")
    {
        $TranscriptFolder = $(Get-Location).Path
    }

Write-Host "Transcripts folder -> $($TranscriptFolder.ToUpper())" -ForegroundColor Cyan;

<#
# open folder browser dialog box to choose a transcripts folder
Add-Type -AssemblyName System.Windows.Forms;

$folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog;
$folderBrowser.Description = "Select the transcripts folder";
$folderBrowser.ShowNewFolderButton = $false;
$folderBrowser.SelectedPath = $(Get-Location).Path;
$folderBrowser.ShowNewFolderButton = $true;

# Show the dialog box
$result = $folderBrowser.ShowDialog();

if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    $TranscriptFolder = $folderBrowser.SelectedPath;
} else {
    Write-Host "Folder selection was canceled.";
    break
}
#>

# Choose the date range to look for powershell audits
$StartDateInput = Read-Host "Type the Start Date to begin looking for transcripts, in format ddMMyyyy`n(e.g. 21092024 - September 21th 2024), or press <Enter> for today's date";

if ($StartDateInput -eq "")
    {
        $StartDateInput = Get-Date -Format ddMMyyyy;
    }

$Dateformat = "ddMMyyyy";
$StartDate = [datetime]::ParseExact($StartDateInput, $Dateformat, $null)
Write-Host "StartDate -> $($StartDate.DateTime)" -ForegroundColor Cyan;

$EndDateInput = Read-Host "Type the End Date to begin looking for transcripts, in format ddMMyyyy, or press <Enter> for today's date";

if ($EndDateInput -eq "")
    {
        $EndDateInput = Get-Date -Format ddMMyyyy;
    }

$EndDate = [datetime]::ParseExact($EndDateInput, $Dateformat, $null)
Write-Host "EndDate -> $($EndDate.DateTime)" -ForegroundColor Cyan;
}

# get file paths recursively
Write-Host "[x] Getting initial file list...";
$filesInFolder = Get-ChildItem -Path $TranscriptFolder -filter *.txt -Recurse | where {$_.PSIsContainer -eq $false}

# Filter by relevant dates
$dateformatFilter = "yyyyMMdd";

$files = $filesInFolder | ForEach-Object {
    $fileDate = [datetime]::ParseExact($_.FullName.Split(".")[3].Substring(0,8), $dateformatFilter, $null);
    if ($fileDate -ge $StartDate -and $fileDate -le $EndDate)
        {
            $_
        }
}

if ($files)
    {
        write-host "[x] Total of $('{0:N0}' -f $files.count) Shell audits found " -ForegroundColor yellow -NoNewline;
    }
else
    {
        write-host "[!] No Shell audits found matching the relevant dates. Quiting." -ForegroundColor Yellow;
        break
    }

# Get unique computers
$Computers = $files.name | ForEach-Object { $_.split(".")[1]}
$ComputersUnique = $Computers | Select-Object -Unique;
Write-Host "from total of " -NoNewline; Write-Host $($ComputersUnique.count) -ForegroundColor Yellow -NoNewline;Write-Host " Unique Computers";

# Parse data - ComputerName, DateTime, HostApplication etc.
Write-Host "Parsing data. Please wait..." -ForegroundColor Cyan;

# Set function to read just the amount of the data we need from the audit logs
function Get-Line {
    [cmdletbinding()]
    param (
    [String]$Path, 
    [Int]$MaxLines
    )
    
    [System.IO.StreamReader] $reader = New-Object `
        -TypeName 'System.IO.StreamReader' `
        -ArgumentList ($path, $true);

    [Int]$MaxLines = 18;
    [int]$currentIndex = 0;

    try
    {
        while ($currentIndex -le $MaxLines)
        {
            $reader.ReadLine()
            $currentIndex++
        }
    }
    catch
    {
        Write-Warning $($Error[0].Exception.Message)
    }
    finally
    {
        $reader.Close();
    }
    return $null;
}

# Set function to read the file contents in case the file is IN USE, by creating a safe handle, with a filestream that uses the handle
function Get-LineInUse {
    [cmdletbinding()]
    param (
    [String]$Path, 
    [Int]$MaxLines = 18
    )
    
Add-Type @"
    using System;
    using System.Runtime.InteropServices;

    public class Kernel32
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile
        );
}
"@

# Define constants
$GENERIC_READ = '0x80000000';
$FILE_SHARE_READ = '0x00000001';
$FILE_SHARE_WRITE = '0x00000002';
$OPEN_EXISTING = 3;
$FILE_ATTRIBUTE_NORMAL = '0x80';

# Open the file with read access, allowing other processes to read and write
$fileHandle = [Kernel32]::CreateFile(
    $Path,
    $GENERIC_READ,
    $FILE_SHARE_READ -bor $FILE_SHARE_WRITE,
    [IntPtr]::Zero,
    $OPEN_EXISTING,
    $FILE_ATTRIBUTE_NORMAL,
    [IntPtr]::Zero
)

# ensure we have the handle, if not - throw error
if ($fileHandle -eq [IntPtr]::Zero) {
    Write-Warning $($Error[0].Exception.Message);
    break
}

# create a SafeFileHandle from the IntPtr file handle
$safeFileHandle = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new($fileHandle, $true)

# create a FileStream using the SafeFileHandle
$fileStream = [System.IO.FileStream]::new(
    $safeFileHandle,
    [System.IO.FileAccess]::Read,
    4096, # Buffer size
    $false # Disable async I/O
)
 
    # Pass the FileStream to the StreamReader
    [System.IO.StreamReader] $reader = [System.IO.StreamReader]::new($fileStream);
    [int]$currentIndex = 0;
    
    try
    {
        while ($currentIndex -le $MaxLines)
        {
            $reader.ReadLine()
            $currentIndex++
        }
    }
    catch
    {
        Write-Warning $($Error[0].Exception.Message)
    }
    finally
    {
        $reader.Close();
    }
    return $null;
}

# Collect data from audit logs
$ShellsData = $files | ForEach-Object {
    #$FileContent = Get-Content $_.fullname -TotalCount 18; # replaced by Get-Line function for FASTER operations
    $TranscriptFile = $_.FullName;
    $FileSizeKB = [math]::Round($_.Length/1kb,2);
    $fileContent = Get-Line -Path $TranscriptFile -ErrorAction SilentlyContinue;
    if ($fileContent)
        {
            $_ | Select-Object @{n='ComputerName';e={$_.name.split(".")[1]}}, @{n='DateTime';e={$_.name.split(".")[3]}}, @{n='HostApplication';e={$($FileContent | Select-String 'Host Application: ').ToString().Replace('Host Application:','').Trim()}}, @{n='UserName';e={$($fileContent | select -First 1 -Skip 3).Replace("Username: ",'')}}, @{n='RunAsUser';e={$($fileContent | select -First 1 -Skip 4).Replace("RunAs User: ",'')}}, @{n='ConfigurationName';e={$($fileContent | Select-String 'Configuration Name: ').ToString().Replace("Configuration Name: ",'')}}, @{n='ProcessID';e={[int]($fileContent | Select-String 'Process ID: ').ToString().Replace("Process ID: ",'')}}, @{n='PSVersion';e={$($fileContent | Select-String 'PSVersion: ').ToString().Replace("PSVersion: ",'')}}, @{n='TranscriptPath';e={$TranscriptFile}}, @{n='FileSizeKB';e={$FileSizeKB}}, @{n='FileStatus';e={"FileClosed"}}, @{n='OSVersion';e={$($fileContent | Select-String 'Machine: ').ToString().Split('(')[1].Replace(')','')}}
        }
    else
        {
            # If file is in use, streamReader would fail to open file content, deliberately, so we use a different function
            #$FileContent = Get-Content $TranscriptFile -TotalCount 18; # this is a slower method with the built-in cmdlet
            $fileContent = Get-LineInUse -Path $TranscriptFile -MaxLines 18; # the faster approach, using PInvoke & a safe handle
            $_ | Select-Object @{n='ComputerName';e={$_.name.split(".")[1]}}, @{n='DateTime';e={$_.name.split(".")[3]}}, @{n='HostApplication';e={$($FileContent | Select-String 'Host Application: ').ToString().Replace('Host Application:','').Trim()}}, @{n='UserName';e={$($fileContent | select -First 1 -Skip 3).Replace("Username: ",'')}}, @{n='RunAsUser';e={$($fileContent | select -First 1 -Skip 4).Replace("RunAs User: ",'')}}, @{n='ConfigurationName';e={$($fileContent | Select-String 'Configuration Name: ').ToString().Replace("Configuration Name: ",'')}}, @{n='ProcessID';e={[int]($fileContent | Select-String 'Process ID: ').ToString().Replace("Process ID: ",'')}}, @{n='PSVersion';e={$($fileContent | Select-String 'PSVersion: ').ToString().Replace("PSVersion: ",'')}}, @{n='TranscriptPath';e={$TranscriptFile}}, @{n='FileSizeKB';e={$FileSizeKB}}, @{n='FileStatus';e={"FileInUse"}}, @{n='OSVersion';e={$($fileContent | Select-String 'Machine: ').ToString().Split('(')[1].Replace(')','')}}
        
            # Last check, in case also the 2nd method of reading the file content didn't work, then set SOME values, at least
            if (!$fileContent)
                {
                    $_ | Select-Object @{n='ComputerName';e={$_.name.split(".")[1]}}, @{n='DateTime';e={$_.name.split(".")[3]}}, @{n='HostApplication';e={"N.A/READ FAILED"}}, @{n='UserName';e={"N.A/READ FAILED"}}, @{n='RunAsUser';e={"N.A/READ FAILED"}}, @{n='ConfigurationName';e={"N.A/READ FAILED"}}, @{n='ProcessID';e={"N.A/READ FAILED"}}, @{n='PSVersion';e={"N.A/READ FAILED"}}, @{n='TranscriptPath';e={$TranscriptFile}}, @{n='FileSizeKB';e={$FileSizeKB}}, @{n='FileStatus';e={"FileFailedOpen"}}, @{n='OSVersion';e={"N.A/READ FAILED"}}
                }
        }
    
}

# Get some common statistics (TOP 10) - to be displayed later, after the open Grid view
$ShellsPerPC = $ShellsData | group Computername; 
$ShellsPerUser = $ShellsData | group UserName;
$ShellsPerRunAsUser = $ShellsData | group RunasUser;
$ShellsPerHostApplication = $ShellsData | group HostApplication;
$ShellsPerPSVersion = $ShellsData | group PSVersion; 
$ShellsPerFileSizeKB = $ShellsData | group FileSizeKB;
$ShellsPerFileStatus = $ShellsData | group FileStatus;
$ShellsPerOSversion = $ShellsData | group OSVersion;

Write-Host "[x] Done parsing.`n" -ForegroundColor Green;

# Save report to CSV
$CSVReportFilename = "$((Get-Location).Path)\PStranscripts_Report_$(Get-Date -Format ddMMyyyyHHMMss).csv";
$ShellsData | Export-Csv $CSVReportFilename -NoTypeInformation;
Write-Host "`n[!] Report saved to -> $CSVReportFilename.`n" -ForegroundColor Green;

## Check option to open in a grid view
if ($OpenResultsInGridView) {
        # Open full Shell audits metadata report
        $Selection = $ShellsData | where {$_.UserName -ne '**********************'} | where {$_.UserName -notlike ""} | # 'Nome utente: ','Nom d'utilisateur : '
            Select datetime, computername, osversion, username, runasuser, hostapplication, FileSizeKB, psversion, processid, configurationname, filestatus, transcriptpath | Sort-Object datetime -Descending | 
                Out-GridView -Title "SELECT ONE OR MORE ENTRIES AND PRESS OK TO OPEN THE FULL TRANSCRIPT FILE <displaying total of $($files.count) Shell audits, from $($ComputersUnique.count) Computer(s), ran as $($ShellsPerRunAsUser.Count) unique Users>" -OutputMode Multiple;

        # If any item(s) selected, open the full transcript in the associated application (e.g. Notepad)
        If ($Selection)
            {
                $Selection | ForEach-Object {Invoke-Item $_.TranscriptPath}
            }
        else
            {
                Write-Host "[!] No item(s) selected for opening/investigation." -ForegroundColor Yellow
            }
        # end of grid report
    }

    else {
        Write-Host "[!] skipped optional grid report" -ForegroundColor Yellow
    }           

<# Show option to open results in a grid view
$Yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Yes";
$No = New-Object System.Management.Automation.Host.ChoiceDescription "&No","No";
$Options = [System.Management.Automation.Host.ChoiceDescription[]]($Yes, $No);
$Title = "Open results in grid?";
$Message = "You can optionally open a Grid-View, displaying $('{0:N0}' -f $files.count) Shell audits, from $('{0:N0}' -f $ComputersUnique.count) Computer(s), ran as $('{0:N0}' -f $ShellsPerRunAsUser.Count) unique Users.`nFrom that grid you can SELECT ONE OR MORE ENTRIES and press OK to OPEN THE FULL TRANSCRIPT FILE.`n"
$Result = $Host.ui.PromptForChoice($Title, $Message, $Options, 0)
        
switch ($Result) {
    0 {        
        # Open full Shell audits metadata report
        $Selection = $ShellsData | where {$_.UserName -ne '**********************'} | where {$_.UserName -notlike ""} | # 'Nome utente: ','Nom d'utilisateur : '
            Select datetime, computername, osversion, username, runasuser, hostapplication, FileSizeKB, psversion, processid, configurationname, filestatus, transcriptpath | sort DateTime | 
                Out-GridView -Title "SELECT ONE OR MORE ENTRIES AND PRESS OK TO OPEN THE FULL TRANSCRIPT FILE <displaying total of $($files.count) Shell audits, from $($ComputersUnique.count) Computer(s), ran as $($ShellsPerRunAsUser.Count) unique Users>" -OutputMode Multiple;

        # If any item(s) selected, open the full transcript in the associated application (e.g. Notepad)
        If ($Selection)
            {
                $Selection | ForEach-Object {Invoke-Item $_.TranscriptPath}
            }
        else
            {
                Write-Host "[!] No item(s) selected for opening/investigation." -ForegroundColor Yellow
            }
        # end of grid report
    }

    1 {
        Write-Host "[!] skipped optional grid report" -ForegroundColor Yellow
    }    
}       
#>

## Next, show a set of common statistics for TOP 10 values (e.g. Top 10 HostApplication used, etc.)

"`nTop Shells by Computername (HUNT HINT: anomalous|sensitive|alert-related hosts, etc.):`n";
$ShellsPerPC |  sort Count -Descending | select count, @{n='Computername';e={$_.Name}} -First 10 | Format-Table -AutoSize;

"`nTop Shells by Username -> The Parent Session Authenticated User (HUNT HINT: anomalous|sensitive|suspicious accounts, etc.):`n";
$ShellsPerUser | sort Count -Descending | select count, @{n='UserName';e={$_.Name}} -First 10 | Format-Table -AutoSize;

"`nTop Shells by RunAsUser -> The Actual UserSession AuthN running the code (HUNT HINT: anomalous|sensitive|suspicious accounts, etc.):`n";
$ShellsPerRunAsUser | sort Count -Descending | select count, @{n='RunAsUser';e={$_.Name}} -First 10 | Format-Table -AutoSize;

"`n*Least common* Shells by HostApplication (HUNT HINT: -enc, bypass, exe other than powershell* or C:\WINDOWS\System32\sdiagnhost.exe, etc.):`n";
$ShellsPerHostApplication | sort Count -Descending | select count, @{n='HostApplication';e={$_.Name}} ,@{n='Computers';e={$_.group | select -ExpandProperty Computername -Unique}} -Last 10 | Format-Table -AutoSize -Wrap;

"`n*Least common* Shells by PSVersion (HUNT HINT: pwsh|less common|older versions, e.g. 5.0.10514.6):`n";
$ShellsPerPSVersion | sort Count -Descending | select count, @{n='PSVersion';e={$_.Name}} -Last 10 | Format-Table -AutoSize;

"`n*Least common* Shells by Operating System version (HUNT HINT: older/'End of life' OS versions):`n";
$ShellsPerOSversion | sort Count -Descending | select Count, @{n='OSVersion';e={$_.Name}}, @{n='Computers';e={$_.group | select -ExpandProperty Computername -Unique}} -Last 10 | Format-Table -AutoSize;

"`nTop Shells by Transcript file size in KB (HUNT HINT: larger than usual files):`n";
$ShellsPerFileSizeKB | Select-Object count, @{n='FileSizeInKB';e={[decimal]$_.name}} | Sort-Object FileSizeInKB -Descending | Select-Object -First 10 | Format-Table -AutoSize;

"`nShells by file status (HUNT HINT: map real-time/active powershell sessions):`n";
$ShellsPerFileStatus | sort Count -Descending | select Count, @{n='FileStatus';e={$_.Name}} | Format-Table -AutoSize;

## wrap up
$ErrorActionPreference = $EAP
Write-Host "[x] Get-PSTranscriptReport completed." -ForegroundColor Green