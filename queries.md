Example Splunk Queries Used

This file contains representative queries used during a SIEM investigation to identify suspicious activity, validate findings, and trace attacker behavior across cloud, endpoint, and network telemetry.

1) Identify Active IAM Users in AWS CloudTrail
index=client3 sourcetype="aws:cloudtrail" user_type="IAMUser"
| stats count by userName
| sort userName

Purpose: Establish a baseline of active IAM users interacting with AWS services.
Why it mattered: Narrowed analysis to human-driven activity and identified identities for deeper investigation.

2) Detect AWS API Activity Without MFA
index=client3 sourcetype="aws:cloudtrail" userIdentity.sessionContext.attributes.mfaAuthenticated="false" NOT eventName="ConsoleLogin"

Purpose: Identify API activity performed without MFA.
Why it mattered: Highlighted potentially risky or unauthorized AWS activity.

3) Identify Public S3 Bucket Exposure
index=client3 sourcetype="aws:cloudtrail" eventSource="s3.amazonaws.com" eventName="PutBucketAcl" AllUsers
| table _time requestParameters.bucketName userIdentity.userName eventName

Purpose: Detect S3 ACL changes granting public access.
Why it mattered: Confirmed that the frothlywebcode bucket was publicly exposed.

4) Measure Uploaded Archive File Size
index=client3 sourcetype="aws:s3:accesslogs" frothlywebcode operation="REST.PUT.OBJECT" ".tar.gz"
| eval size_mb = round(object_size / 1024 / 1024, 2)
| table key size_mb

Purpose: Identify uploaded archive files and measure size.
Why it mattered: Validated suspicious activity within the exposed bucket.

5) Detect Cryptomining DNS Activity
index="client3" sourcetype="stream:dns" host="*-L"
| lookup coinminingdomains.csv Domain AS query OUTPUT Domain AS matched_domain
| search matched_domain=*
| stats dc(matched_domain) as distinct_mining_destinations

Purpose: Correlate DNS queries with known mining domains.
Why it mattered: Confirmed communication with cryptomining infrastructure.

6) Identify High CPU Mining Behavior
index=client3 sourcetype=PerfmonMk:Process host="BSTOLL-L"
| eval high_cpu=if(process_cpu_used_percent >= 90, 1, 0)
| stats count, earliest(_time) as et, latest(_time) as lt, max(Elapsed_Time) as elapsed,
min(process_cpu_used_percent) as min_cpu,
max(process_cpu_used_percent) as max_cpu,
avg(process_cpu_used_percent) as avg_cpu,
sum(high_cpu) as high_cpu_samples by host, process_name, process_id
| where elapsed >= 300
| eval risk_score = (high_cpu_samples / elapsed) * 100
| convert ctime(et), ctime(lt)
| sort - risk_score

Purpose: Detect sustained high-CPU processes.
Why it mattered: Identified cryptomining activity tied to specific processes.

7) Investigate Compromised AWS Access Key
index=client3 sourcetype="aws:cloudtrail" userIdentity.accessKeyId=AKIAJOGCDXJ5NW5PXUPA eventName="DescribeAccountAttributes"
| table _time eventName eventSource userAgent sourceIPAddress

Purpose: Trace activity tied to a compromised access key.
Why it mattered: Revealed attacker reconnaissance behavior and tooling.

8) Detect Malicious OneDrive Uploads
index="client3" sourcetype="*o365:management*" Workload="OneDrive" Operation="FileUploaded" lnk
| table _time sourcetype src_ip user object SourceFileName UserAgent

Purpose: Identify suspicious .lnk file uploads.
Why it mattered: Helped trace user-driven malicious activity.

9) Detect New User Account Creation
index=client3 sourcetype="WinEventLog" EventCode=4720
| eval CreatedBy = mvindex(Account_Name, 0)
| eval NewUser = mvindex(Account_Name, 1)
| table _time CreatedBy NewUser host

Purpose: Identify new user accounts post-compromise.
Why it mattered: Revealed persistence mechanisms.

10) Identify C2 Communication
index=client3 "/admin/get.php"
| table _time host sourcetype src_ip dest_ip uri_path Message

Purpose: Pivot on known C2 URI.
Why it mattered: Identified compromised hosts communicating with attacker infrastructure.

11) Detect Obfuscated PowerShell
index=client3 source=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104 host=FYODOR-L FromBase64String

Purpose: Detect encoded PowerShell execution.
Why it mattered: Exposed attacker obfuscation techniques.

12) Identify Scanning Behavior
index=client3 host="FYODOR-L" source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationPort'>(?<DestinationPort>\d+)</Data>"
| stats dc(DestinationPort) as DestinationPortDistinctCount by Image
| sort - DestinationPortDistinctCount

Purpose: Detect port scanning activity.
Why it mattered: Identified malicious binary behavior.

13) Investigate Linux Privilege Escalation
index=client3 sourcetype="osquery:results" tomcat8 columns.cmdline=*
| table _time siemevid host columns.path columns.pid columns.uid decorations.username columns.cmdline
| reverse

Purpose: Analyze command-line activity on Linux host.
Why it mattered: Revealed privilege escalation and payload staging.

14) Detect File Staging in /tmp
index=client3 /tmp/* sourcetype="wineventlog"
| dedup Process_Command_Line
| table _time Process_Command_Line
| reverse

Purpose: Identify file creation activity in /tmp.
Why it mattered: Confirmed attacker payload delivery.

15) Detect Exchange Transport Rule Creation
index=client3 sourcetype="ms:o365:management" Workload=Exchange Operation=New-TransportRule
| table _time UserId Operation Parameters Name siemevid Parameters{}.Name Parameters{}.Value

Purpose: Identify suspicious email rule creation.
Why it mattered: Revealed attacker persistence via email exfiltration rules.

Summary

These queries demonstrate a full investigation workflow including:

AWS cloud activity analysis
Endpoint monitoring (Sysmon, osquery)
Network and DNS correlation
Authentication and identity tracking
Email and O365 investigation

The investigation emphasized:

Log correlation across multiple sources
Detection of attacker behavior patterns
Identification of indicators of compromise
Reconstruction of attack progression
