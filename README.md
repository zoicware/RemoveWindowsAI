# Remove Windows Ai
## Why?
The current 24H2 build of Windows 11 and future builds will include increasingly more AI features and components. This script aims to remove ALL of these features to improve user experience, privacy and security. 

<img width="150" alt="AI-Explorer-icon" src="https://github.com/zoicware/RemoveWindowsAI/assets/118035521/33efb033-c935-416c-977d-777bb69a3737">


----------------------



### Script Features
 - **Registry** 
   - Disable Copilot, Recall, Input Insights, CoPilot in Edge, Image Creator in Paint, Remove AI Fabric Service
 - Remove all AI appxpackages and force remove the files
 - Disable Copilot policies in IntegratedServicesRegionPolicySet.json
 - Remove Recall Optional Feature
 - Remove all hidden Copilot installers
 - Disable Rewrite for Notepad
 - Delete any screenshots and data stored by Recall
 - Remove Recall Scheduled Task
 - Remove Machine Learning DLL's
 - Remove Hidden AI CBS Packages
  
### Read More In Depth Here
> **[Documentation](https://github.com/zoicware/RemoveWindowsAI/blob/main/Documentation.md)**

---

> [!IMPORTANT]  
> **HELP WANTED**
>
> Currently, the script contains appx packages installed on Copilot+ PCs however, there could be more on different configurations as well as other features
> 
> If you have one of these PCs submit an issue so we can check if the script is missing anything

---

 ### How to Use
 **Run From Powershell Console as Administrator**
 ```PowerShell
 iwr https://raw.githubusercontent.com/zoicware/RemoveWindowsAI/main/RemoveWindowsAi.ps1 | iex
 ```
 


![image](https://github.com/user-attachments/assets/be4c29da-8a60-43e7-a63b-5d4415cc31a6)

---

### Updates

Given that Microsoft are continually updating and adding new AI features this script will attempt to stay updated for the newest stable build.

 > [!NOTE]  
> Any feature added to an insider build will not be added to this script till it's added to the latest stable release

 
> [!TIP]
> **Submitting An AI Feature**
>
> If you find an AI feature or registry key that is not currently removed or disabled by the script submit an issue with as much information as possible and I will add it to the script.


### Join The Discord

[![Discord](https://discordapp.com/api/guilds/1173717737017716777/widget.png?style=banner1)](https://discord.gg/VsC7XS5vgA)


