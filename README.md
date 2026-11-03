# Intel Bluetooth driver update block

Intune remediation pair that hides Intel Bluetooth driver updates 24.70.0.4 and 24.80.0.2, removes a downloaded or staged copy of those versions, and leaves the Bluetooth driver that is already in use.

## Why a default search is not enough

Settings can offer a driver from Microsoft Update, as an optional update, or from the Update Orchestrator store. A searcher created with the default service and `IsInstalled=0` can miss that offer and report the device compliant.

These scripts register Microsoft Update for scanning only, search each update service, and read UpdateStore files as UTF-16 as well as UTF-8. Hiding is done on the Windows Update Agent update object. The PSWindowsUpdate hide cmdlet is not used.

## Files

Both files are the same script. Intune runs each file with no arguments, so the default `-Mode` is the only difference.

- `Detect-IntelBTDriverUpdate.ps1` exits 0 when those versions are not offered, downloaded, or staged. Exit 1 means the offer is still present, or the scan could not see Microsoft Update or the Update Orchestrator store.
- `Remediate-IntelBTDriverUpdate.ps1` hides the offer, deletes only the matching download folder and UpdateStore file, removes a staged `oemXX.inf` that is not the live adapter driver, and checks again.

Upload the files into Intune. Do not paste them through chat. Brackets in type names can be stripped.

## Intune settings

- Run this script using the logged-on credentials: No
- Run script in 64-bit PowerShell: Yes
- Enforce script signature check: No, unless the files are signed
- Schedule: Daily. Use hourly only while a device still shows the offer.

A failure to reach Microsoft Update is reported as non-compliant, unless policy blocks connections to Windows Update internet locations. Assign the package to one device before a broad assignment.

Declining the driver in each Intune driver update policy is what stops a managed re-offer. A local hide does not override a driver that policy still approves.

## What the scripts do not change

- They do not set `ExcludeWUDriversInQualityUpdate`.
- They do not delete `SoftwareDistribution\DataStore`.
- They do not clear `RebootRequired`.
- They do not remove the Bluetooth driver bound to the adapter. `pnputil /delete-driver` is called without `/force` or `/uninstall`.
- They match a version only when the update is Intel and Bluetooth, or the Bluetooth class GUID `{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}`, and only for 24.70.0.4 or 24.80.0.2. An Intel network driver is left alone.

The log is `%ProgramData%\IntelBTDriverBlock\IntelBTDriverUpdate.log`.

## Check

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Detect-IntelBTDriverUpdate.ps1 -Mode SelfTest
```

SelfTest does not contact Windows Update. On a device, run each file with no arguments in 64-bit Windows PowerShell as SYSTEM.
