# Investigating-Windows-Challenge
  A comprehensive guide to solving the "Investigating Windows" challenge
  https://tryhackme.com/room/investigatingwindows

# Table of Contents
  -Introduction  
  -Introduction
  -Step-by-Step Guide
  -Final Answers
  -Key Learnings
  -Contribution

# Introduction
This repository documents the complete forensic investigation of a compromised Windows system from TryHackMe's "Investigating Windows" challenge. The attacker left multiple traces that we'll uncover through:
  -Windows Event Log Analysis
  -Registry Artifact Examination
  -Malicious Process Identification
  -C2 Communication Patterns
  -Persistence Mechanism Discovery

# Prerequisites
  Tools Needed:
    - Access to TryHackMe's Windows machine
    - PowerShell 5.1+
    - Sysinternals Suite (optional)

  Knowledge Requirements:
    - Basic Windows command line
    - Understanding of:
      - Windows Event IDs
      - Registry structure
      - Common attack vectors


# Step-by-Step Guide
 # Get OS version
Get-ComputerInfo | Select-Object OsName, OsVersion, OsArchitecture

# Check installed patches
Get-HotFix | Sort-Object InstalledOn -Descending

# User Account Investigation
  # List all local users
  Get-LocalUser | Select-Object Name, Enabled, LastLogon, SID

  # Check privileged accounts
  Get-LocalGroupMember -Group "Administrators"

# Process Analysis
  # List running processes
Get-Process | Select-Object Id, ProcessName, Path

  # Check network connections
Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort

  # Check autorun entries
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

  # Recent commands
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"

  # Filter security events
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4688,4624,4672
} -MaxEvents 50

  # Running Processes
Get-Process | Select-Object Id,ProcessName,Path,Company | Sort-Object CPU -Descending

  # Network Connections
Get-NetTCPConnection -State Established | 
    Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess |
    Sort-Object RemoteAddress



# Key Learnings
  Registry Check: Run and RunOnce Paths Should Always Be Checked
  Hosts File Analysis: Unusual Changes Are a Sign of DNS Spoofing
  Security Logs: Event ID 4688 to Check Process Execution

# Common Intrusion Signs
  Executable Files in Temporary Paths
  Network Connections to Unknown IPs
  Scheduled Tasks with Common Names

  
