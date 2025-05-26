# Remove Windows Ai
## Why?
With the upcoming 24H2 Update to Windows 11 Microsoft will begin to implement Copilot and Recall. These features are a major security risk and very intrusive to the users experience. 

<img width="150" alt="AI-Explorer-icon" src="https://github.com/zoicware/RemoveWindowsAI/assets/118035521/33efb033-c935-416c-977d-777bb69a3737">


----------------------



### Script Features
 - **Registry** 
   - Disable Copilot, Recall, Input Insights, CoPilot in Edge, Image Creator in Paint
 - Remove all AI appxpackages and force remove the files
 - Disable Copilot policies in IntegratedServicesRegionPolicySet.json
 - Remove Recall Optional Feature
 - Remove all hidden Copilot installers
 - Disable Rewrite for Notepad
 - Delete any screenshots and data stored by Recall

 ### How to Use
 **Run From Powershell Console as Administrator**
 ```
 iwr https://raw.githubusercontent.com/zoicware/RemoveWindowsAI/main/RemoveWindowsAi.ps1 | iex
 ```
 


![image](https://github.com/user-attachments/assets/be4c29da-8a60-43e7-a63b-5d4415cc31a6)


