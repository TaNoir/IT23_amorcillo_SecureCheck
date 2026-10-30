> **You do this phase by hand — do not give it to Antigravity.**

## Phase 0 — Lab setup (you do this, by hand)

**Goal:** A Windows laptop that runs the app, plus 2 test VMs that the app can audit over remote PowerShell.

### 0.1 Install on your Windows laptop
- **.NET 8 SDK** (LTS) — check with `dotnet --version` (should be 8.x).
- **Visual Studio 2022** (Community) with the *ASP.NET and web development* workload, or VS Code with the C# Dev Kit extension.
- **SQL Server 2022 Express** (choose *Basic* install) and **SQL Server Management Studio (SSMS)**.
- **Git**, and **VirtualBox** (or VMware Workstation).

### 0.2 Create 2 test VMs
- Use **Windows 10 or Windows 11 Enterprise Evaluation** ISOs (free, 90 days, from the Microsoft Evaluation Center). Optional third VM: Windows Server 2019/2022 Evaluation.
- Avoid the Windows Server 2012 R2 ISO for testing — it has PowerShell 4.0, which lacks some cmdlets the audit uses (`Get-LocalUser`, `Get-MpComputerStatus`).
- Name them `SC-LAB-01` (will be the **weak** PC) and `SC-LAB-02` (will be the **secure** PC).
- Give each VM 2 CPUs, 4 GB RAM, 50 GB disk.
- **Network:** Adapter 1 = NAT (internet for updates), Adapter 2 = **Host-only Adapter** (so the laptop can reach the VM). Note each VM's host-only IP with `ipconfig` (usually `192.168.56.x`).
- On each VM create a local admin account, e.g. user `scaudit`, and set a password.

### 0.3 Turn on remote PowerShell on each VM (run PowerShell **as Administrator** on the VM)
```powershell
# Make the host-only network "Private" (WinRM refuses Public networks by default)
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private

# Turn on PowerShell Remoting (WinRM)
Enable-PSRemoting -Force

# LAB ONLY: let local admin accounts get full admin rights over the network.
# Needed in a workgroup (no domain), otherwise you get "Access is denied".
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force

# Allow ping from the laptop (optional, helps testing)
Enable-NetFirewallRule -Name FPS-ICMP4-ERQ-In
```

### 0.4 Let your laptop connect to the VMs (run PowerShell **as Administrator** on the laptop)
```powershell
Start-Service WinRM
# Trust the VM IPs (workgroup computers are not trusted automatically)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.56.*" -Force
```

### 0.5 Test it (on the laptop)
```powershell
$cred = Get-Credential   # enter SC-LAB-01\scaudit and its password
Invoke-Command -ComputerName 192.168.56.101 -Credential $cred -ScriptBlock { $env:COMPUTERNAME; $PSVersionTable.PSVersion }
```
**Done when:** it prints the VM name and PowerShell version 5.1 for **both** VMs.

> In a real school with a domain, steps 0.3–0.4 are done once for all PCs using Group Policy, and TrustedHosts / LocalAccountTokenFilterPolicy are not needed. This is what the proposal describes.
