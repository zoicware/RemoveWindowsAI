## Remove Windows AI Documentation
---
### OS Support

- The script is created for any version of Windows 10 and Windows 11, Latest Stable Builds
- For best results use a Pro, Enterprise, Server, or Education version. I can not guarentee 100% removal on Home versions
  - If you are on a Home version and want to convert to pro I recommend using massgrave: https://github.com/massgravel/Microsoft-Activation-Scripts
> [!NOTE]
> The script will work on Insider builds however, any new ai features added to insider builds will not be added to the script till they are released in the latest stable build
>

---

### Code Review

- Given that Microsoft REALLY do not want users removing all AI features the script uses some advanced techniques in PowerShell

#### Run-Trusted Function

- This function leverages an exploit allowing code execution under the `TrustedInstaller.exe` service also known as `Windows Module Installer`
  - Various PowerShell commands will be ran hidden from the user allowing the script to remove items and packages that are locked via System Privileges
 
#### Registry Keys
- I have collected all registry keys regarding AI disablement, including Notepad, Paint, and Edge.
  - Some of these are Group Policies so if you see any AI feature settings greyed out with the message `Some Settings are Managed by Your Organization` this is why
 
#### Copilot Nudges Removal
- These registry entries are related to what Microsoft calls `Nudges`, personalized notifications with tips regarding Copilot

#### Disable Copilot In IntegratedServicesRegionPolicySet
- This json file contains rules for deciding weither or not certain apps and settings are enabled based on your region
  - This is mainly used for the EEA [European Economic Area]
- The script finds all policies related to Copilot and sets the default state to disabled 


#### Appx Package Removal
- While the main Copilot package can be removed without any special tricks (Remove-AppxPackage) most AI packages are marked as `Non-Removeable` therefore, the script needs to use multiple exploits to remove these
 - The script creates a sub script in `%TEMP%` to be ran under the above mentioned function `Run-Trusted`
   - **Exploits Performed**
     
     - **End of Life**: one way to trick Windows into thinking a locked package can be removed is to add its Package Family Name to `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\USERSID`
       - To avoid Windows Update from failing these registry entries are removed once the package is confirmed uninstalled
     - **Deprovisioning**: this adds the Package Family Name to `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned` this will prevent the package from being reinstalled by Windows Update
     - **Set-NonRemovableAppsPolicy**: this dism command will attempt to remove the `Non-Removeable` property mentioned above and needs to have system privileges to work
     - **Removing Inbox Apps**: some packages are marked as `InboxApps` this prevents the user from removing them however, when the package is removed from the `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications` via Run-Trusted Windows will no longer recognize it as an Inbox App

#### Recall Optional Feature
- On most systems recall will be installed via an optional feature, the script will disable and remove this resulting in the State of: `DisabledWithPayloadRemoved`

#### Hidden AI CBS Packages
- Windows CBS [Component-Based Servicing] contains windows packages where some can be visible and removable via `get-windowspackage` and `remove-windowspackage` respectfully
  - Most packages are not visible to the dism command by default so a few tricks are needed to enable this and allow for removal
- The script will search for packages containing various AI keywords in `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages`
  - To enable visualzation and allow for removal the `Visibility` key needs to be set to 1 and the subkeys `Owners` and `Updates` need to be removed
 
#### Removing AI Files and Folders
- The script will forcibly remove the Appx package install locations, remove Machine Learning Dlls, and hidden Copilot installers.


