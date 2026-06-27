# How to Contribute

## Steps to get started

1. Fork this repository
2. Make your desired changes/additions
3. Create a pull request and select your fork and branch
4. Give a detailed description as to what changes you made and why you made them

## Tips for making a good PR

1. A PR should be 1 small change or a few small related changes. 
2. Code should follow the scripts formatting and style. I recommend using the auto formatter in vscode for powershell
   
     *Specfics: Variable names preferablly written in camel case, comments should limited but meaningful, no powershell cmdlet aliases allowed, avoid using named blocks in functions like `begin,process,etc`, avoid using excessive pipes to create 1 liners*
4. **AI USE** - AI can be used to assist in the coding process HOWEVER I will know if its blantly vibe coded meaning YOU did not write,edit, or improve the code in anyway. These PRs will not be merged.
5. Code should follow the existing project structure, this means if you need to create a new function it should be made in the main script, do not create a seperate powershell script
6. Create a meaningful change, this could be fixing a bug, adding a widely requested feature, adding a new ai feature to disable or remove

  #### Examples of what not to do
  https://github.com/zoicware/RemoveWindowsAI/pull/102
  https://github.com/zoicware/RemoveWindowsAI/pull/130
  https://github.com/zoicware/RemoveWindowsAI/pull/215
