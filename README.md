# Get-PSTranscriptReport
PowerShell Transcripts Analysis &amp; Reporting - analyzes PSTranscriptions folder content, provides insights and some hunting guidance
<br><br>
Sample usage:
<br><b>
.\Get-PSTranscriptReport.ps1
</b><br>
Runs the scripts without prior configuration, and promprs the user for required information.<br>
Prompts in the CLI will include the Transcripts folder location (local or network, e.g. \\SRV\trans$), The Start Date to begin looking for transcripts, in format ddMMyyyy (e.g. 21092024 - September 21th 2024), or press <Enter> for today's date, and the End Date to begin looking for transcripts, in format ddMMyyyy, or press <Enter> for today's date.
<br><br><b>
.\Get-PSTranscriptReport.ps1 -Jsonfile .\PSTranscriptParameters.json -OpenResultsInGridView
</b><br>
Runs the scripts using the settings inside the json file, which include:<br>
Transcript Folder location (Can also be a network share/UNC), Start Date (to lookup transcripts from that date), End Date (to lookup transcripts until and including that date).<br><br>
The <b>-OpenResultsInGridView</b> optional switch will open an ad-hoc grid when finished parsing, allowing you to select and look into specific Transcrips.</b><br><br>
<b>Report is saved to CSV.</b><br><br>
Analyzed data includes:<br>
<b>
datetime<br>Computername<br>OSversion<br>Username<br>RunAsUser<br>hostApplication<br>FileSizeKB<br>psversion<br>ProcessID<br>configurationName<br>filestatus<br>transcriptPath<br><br></b>

Some common statistics generated by the tool may include:<br>
<b>
Top Shells by Computername</b> (HUNT HINT: anomalous|sensitive|alert-related hosts, etc.)<br><b><br>
Top Shells by Username -> The Parent Session Authenticated User</b> (HUNT HINT: anomalous|sensitive|suspicious accounts, etc.)<br><b><br>
Top Shells by RunAsUser -> The Actual UserSession AuthN running the code</b> (HUNT HINT: anomalous|sensitive|suspicious accounts, etc.)<br><b><br>
*Least common* Shells by HostApplication</b> (HUNT HINT: -enc, bypass, exe other than powershell* or C:\WINDOWS\System32\sdiagnhost.exe, etc.)<br><b><br>
*Least common* Shells by PSVersion</b> (HUNT HINT: pwsh|less common|older versions, e.g. 5.0.10514.6)<br><b><br>
*Least common* Shells by Operating System version</b> (HUNT HINT: older/'End of life' OS versions)<br><b><br>
Top Shells by Transcript file size, in KB</b> (HUNT HINT: larger than usual files)<br><b><br>
Shells by file status, InUse or not</b> (HUNT HINT: map real-time/active powershell sessions)<br>
</b>
