# Remove Windows Ai
## Why?
The current 25H2 build of Windows 11 and future builds will include increasingly more AI features and components. This script aims to remove ALL of these features to improve user experience, privacy and security. 

<img width="150" alt="AI-Explorer-icon" src="https://github.com/zoicware/RemoveWindowsAI/assets/118035521/33efb033-c935-416c-977d-777bb69a3737">


----------------------



### Script Features
 - **Disable Registry Keys** 
   - Disable Copilot
   - Disable Recall
   - Disable Input Insights and typing data harvesting 
   - Copilot in Edge
   - Image Creator in Paint
   - Remove AI Fabric Service
   - Disable AI Actions
   - Disable AI in Paint
   - Disable Voice Access
   - Disable AI Voice Effects
   - Disable AI in Settings Search
 - **Prevent Reinstall of AI Packages**
   - Installs custom Windows Update package to prevent reinstall of AI packages in the CBS (Component-Based Servicing) store 
 - **Disable Copilot policies** 
   - Disables policies related to Copilot and Recall in IntegratedServicesRegionPolicySet.json
 - **Remove AI Appx Packages**
   - Removes all AI appx packages including `Nonremovable` packages and WindowsWorkload 
 - **Remove Recall Optional Feature**
 - **Remove AI Packages in CBS**
   - This will remove hidden and locked AI packages in the CBS (Component-Based Servicing) store 
 - **Remove AI Files**
   - This will do a full system cleanup removing all remaining AI installers, registry keys, and package files 
 - **Hide AI Components**
   - This will hide the settings page `AI Components` 
 - **Disable Rewrite AI Feature in Notepad**
 - **Remove Recall Tasks**
   - Forcibly removes all instances of Recall's scheduled tasks  
 
#### Manual AI Disabling
- Unfortunately, not all features and settings can be disabled via a script. This guide will show additional AI features to disable.
> **[Disable Other AI Features](https://github.com/zoicware/RemoveWindowsAI/blob/main/OtherAIFeatures.md)**
  
### Read the Script Docs Here
  > **[Documentation](https://github.com/zoicware/RemoveWindowsAI/blob/main/Documentation.md)**

  > [!WARNING]
  > Some third party anti-viruses will falsely detect the script as malicious, obviously this is a false positive and the anti-virus will need to be temporarily disabled or set the script as an exclusion.
  >
  > Due to the nature of making advanced changes to the system many debloat tools/scripts will be falsely detected as malware... if you are unsure about the script I always recommend testing any software in a virtual machine first

---


 ### How to Use
 
 #### Run From Powershell Console as Administrator
 ---

 > [!WARNING]
 > Running the script with PowerShell 7 can cause issues, to avoid this ensure you are running Windows PowerShell (5.1)
 >

 ### Launch with UI
 ```PowerShell
 & ([scriptblock]::Create((irm "https://raw.githubusercontent.com/zoicware/RemoveWindowsAI/main/RemoveWindowsAi.ps1")))
 ```
 ### Compact Command:
 ##### Link shortened using open source link shortener: https://kutt.it/
 ```PowerShell
 & ([scriptblock]::Create((irm 'https://kutt.it/RWAI')))
 ```

 <details>  
  <summary>Click to View UI</summary>
  <img width="586" height="693" alt="Capture2" src="https://github.com/user-attachments/assets/92499461-f0d3-40f3-94f6-6d7a0d49fc10" />
</details>  

&nbsp;

### Command Line Options

**Run in Non-Interactive Mode with All Options**
 ```PowerShell
 & ([scriptblock]::Create((irm "https://raw.githubusercontent.com/zoicware/RemoveWindowsAI/main/RemoveWindowsAi.ps1"))) -nonInteractive -AllOptions
 ```

--- 

**Run with Specific Options Example**
 ```PowerShell
 & ([scriptblock]::Create((irm "https://raw.githubusercontent.com/zoicware/RemoveWindowsAI/main/RemoveWindowsAi.ps1"))) -nonInteractive -Options DisableRegKeys,RemoveAppxPackages,DisableCopilotPolicies 
 ```

**All Possible Options:**
```
DisableRegKeys          
PreventAIPackageReinstall     
DisableCopilotPolicies       
RemoveAppxPackages        
RemoveRecallFeature 
RemoveCBSPackages         
RemoveAIFiles               
HideAIComponents            
DisableRewrite      
RemoveRecallTasks
```


**Run with Backup Mode Enabled**

> [!NOTE]
> Backup Mode needs to be enabled to be able to fully revert
> 
 ```PowerShell
 & ([scriptblock]::Create((irm "https://raw.githubusercontent.com/zoicware/RemoveWindowsAI/main/RemoveWindowsAi.ps1"))) -nonInteractive -backupMode -AllOptions
 ```

---

**Revert Changes**

 ```PowerShell
 & ([scriptblock]::Create((irm "https://raw.githubusercontent.com/zoicware/RemoveWindowsAI/main/RemoveWindowsAi.ps1"))) -nonInteractive -revertMode -AllOptions
 ```

---

### Updates

Given that Microsoft are continually updating and adding new AI features this script will attempt to stay updated for the newest stable build.

You can view the newest updates to the script here:
https://github.com/zoicware/RemoveWindowsAI/commits/main/

 > [!NOTE]  
> Any feature added to an Insider build will not be added to this script till it's added to the latest stable release

 
> [!TIP]
> **Submitting an AI Feature**
>
> If you find an AI feature or registry key that is not currently removed or disabled by the script submit an issue with as much information as possible and I will add it to the script.


### Donation 

If you would like to support my work consider donating :)

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/zoicware)


### Join The Discord

[![Discord](https://discordapp.com/api/guilds/1173717737017716777/widget.png?style=banner1)](https://discord.gg/VsC7XS5vgA)


### YT Guide
#### [How to Remove ALL Windows AI Features](https://youtu.be/j5_eEBWGHFw)














