# Audit-WindowsAI.ps1

A local audit + targeted-uninstall layer on top of
[zoicware/RemoveWindowsAI](https://github.com/zoicware/RemoveWindowsAI).

Where the upstream `RemoveWindowsAi.ps1` rips **everything** AI out of Windows, this script takes a
more surgical, repeatable approach: it **audits** what AI is on the machine, **reports** it next to
a text log, and then **removes the product AI features while keeping the on-device AI runtime + local
LLM intact** so third-party apps (Windows ML / Windows AI Foundry) keep working.

It is built to be **re-run after every Windows Update**: it checks for things that are *not* on the
PC right now but Microsoft can push back at any time (Recall, CBS packages, scheduled tasks, services,
policy keys). Anything missing is reported as "not present / ready to be handled", and in removal mode
the disable values are written pre-emptively, so the feature will not come up if it returns.

---

## Why this exists

- The upstream script is all-or-nothing and also strips the **base AI runtime** (ONNX/WinML, Phi
  Silica, OpenVINO NPU provider). On a Copilot+ PC those are useful to keep for *your own* apps that
  call the local models.
- Microsoft re-adds AI packages after cumulative updates. A one-shot removal is not enough — you need
  an **idempotent audit** you can run again and again.
- You want a written record of what was found and what was changed (the `AI-Audit-<timestamp>.txt`
  report).

---

## The two modes

| Mode | What it removes | What it keeps |
|---|---|---|
| **foundation** (default) | Microsoft product AI: Copilot, Click to Do, AI search, Office/Paint/Photos AI, Voice Access, Gaming Copilot, Input Insights, AI Actions, Recall | Base runtime + local LLM: ONNX/WinML, Phi Silica, OpenVINO, tokenizer, OCR, content-moderation/safety layers |
| **-RemoveAllAI** | Everything, including the runtime/LLM and the legacy `Windows.AI.MachineLearning.dll` inbox API | Nothing AI-related |

The keep-list lives at the top of the script as editable arrays (`$keepPatterns`, `Test-Keep`,
`$keepRegKeys`). Move a pattern in or out to change the policy.

### Foundation guarantee

In foundation mode the script **never** turns off app access to the local AI models. The four
"gateway" values — `generativeAI` / `systemAIModels` consent and `LetAppsAccess*` — are held at
`Allow`/`1` by `$keepRegKeys`, and `restore-high-risk.reg` is re-imported at the very end of the
removal pass so it always wins. The ~80 disable keys deliberately exclude those four.

---

## What it checks and does

The audit runs top-to-bottom and prints each section (also written to the report). In removal mode the
matching action runs after a single confirmation prompt.

1. **Appx packages** — splits matched AI packages into *to remove* vs *kept (foundation/LLM)*. Patterns
   not currently present are listed so you can see what would be caught on return.
2. **Provisioned packages** — same split for the provisioned (per-image) packages.
3. **Files on disk** — Copilot settings DLLs, App Actions / Visual Assist binaries, `ActionsMcpHost`,
   Office AI folders, Edge Copilot installers, InboxApps Copilot, `CoreAIPlatform*` (Recall/CoreAI data),
   OneDrive "Microsoft Copilot Chat Files", and the install/LocalAppData folders of removed packages.
4. **AI services** — stops and disables (`Start=4`, reversible) `WSAIFabricSvc` and
   `MicrosoftCopilotElevationService`. `AarSvc*` (shared Agent Activation Runtime) is **reported only**,
   not touched.
5. **Registry — disable keys** (~80 values, grouped): Recall/WindowsAI, Copilot, Search/Input/Privacy
   (Input Insights, inking & typing, voice activation), Voice Access, AI Actions (FeatureManagement
   overrides), Paint AI, Edge Copilot (~15 policies), Office Copilot (per-app `EnableCopilot`), Notepad
   Rewrite. Each is reported as `OK` / `diff` / `missing`; in removal mode it is **set even if the key is
   missing** (the pre-emptive guard).
6. **Registry — leftover + protective** — deletes leftover app keys, URI handlers
   (`ms-copilot` / `ms-office-ai` / `ms-clicktodo`), the `.copilot` association; and verifies the four
   protective keep values stay on.
7. **CBS hidden packages** — scans the Component Based Servicing store for `AIX | Recall | Copilot |
   CoreAI`, un-hides them (`Visibility=1`, `DefVis=2`, drop `Owners`/`Updates`) and removes them so a
   future update can't silently reinstall.
8. **Recall + scheduled tasks** — detects the Recall optional feature (incl.
   `DisabledWithPayloadRemoved`), the `*WindowsAI*` / `*Office Actions Server*` scheduled tasks, and the
   `TaskCache\Tree` leftovers (resolving the GUID `Id` to clean the matching `TaskCache\Tasks\<GUID>`).
9. **Region policy** — `IntegratedServicesRegionPolicySet.json`: sets Copilot/Recall policies to
   `disabled` and A9/Settings-Agent policies to `enabled`.
10. **Hide AI Components** — sets `SettingsPageVisibility = hide:aicomponents;appactions;`.

A **SUMMARY** block totals every category, then the script either prompts or (with `-Remove -Yes`)
proceeds straight to the removal pass.

> **Note on a clean machine:** it is normal for many disable keys to report `missing` — those features
> were simply never installed. The script then sets them pre-emptively so the feature stays blocked if
> Windows Update brings it back. This is the intended behaviour.

---

## Requirements

- **Windows PowerShell 5.1** (`powershell.exe`) **as Administrator** — needed for the Appx cmdlets.
  If launched in PowerShell 7 or without admin, the script **relaunches itself via UAC** with the same
  switches.
- For non-removable packages it uses a **TrustedInstaller** exploit (the `sc.exe binPath` method ported
  from the upstream script) to run removal under SYSTEM/TI rights.

---

## Usage

```powershell
# Audit only — change nothing, just report (recommended first run)
.\Audit-WindowsAI.ps1 -AuditOnly

# Audit, then interactively confirm removal
.\Audit-WindowsAI.ps1 -Remove

# Fully non-interactive removal (e.g. scheduled / scripted)
.\Audit-WindowsAI.ps1 -Remove -Yes

# Nuke everything including the runtime/LLM
.\Audit-WindowsAI.ps1 -Remove -Yes -RemoveAllAI
```

If you need to run it yourself from this session's prompt, prefix with `!`:

```
! powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\ins\scripts\Windows RemoveAI\Audit-WindowsAI.ps1" -AuditOnly
```

### Switches

| Switch | Effect |
|---|---|
| `-Remove` | After the audit, offer / perform the removal. |
| `-Yes` | No confirmation prompt (with `-Remove` = fully non-interactive). |
| `-AuditOnly` | Audit only, remove nothing, do not prompt. |
| `-RemoveAllAI` | Ignore the foundation keep-list and remove **everything**, incl. runtime/LLM. |
| `-NoTrustedInstaller` | Do not use the TrustedInstaller trick (standard uninstall only). |
| `-SkipProtect` | Do not re-apply `restore-high-risk.reg` (leave the keep values as-is). |
| `-SkipCBS` | Skip scanning/removing hidden AI packages in the CBS store. |
| `-SkipServices` | Skip disabling AI services. |
| `-SkipRegionPolicy` | Do not edit `IntegratedServicesRegionPolicySet.json`. |
| `-SkipHide` | Do not hide the "AI Components" page in Settings. |
| `-Report <path>` | Custom report path (default: `AI-Audit-<timestamp>.txt` next to the script). |

All switches are passed through when the script relaunches via UAC.

---

## Output

- Console output is colour-coded: **red** = to remove, **green** = clean / kept, **yellow** =
  attention (missing/diff), **dark gray** = not present.
- The same text is written to **`AI-Audit-<timestamp>.txt`** next to the script (or `-Report <path>`).

---

## Companion files in this folder

- **`RemoveWindowsAi.ps1`** — the upstream zoicware script this layer is built on.
- **`restore-high-risk.reg`** — the protective values that keep app access to local AI models enabled;
  re-imported at the end of every removal pass (unless `-SkipProtect`).

---

## Safety notes

- The CBS removal and the on-disk deletion of shell binaries (App Actions / Visual Assist) are the most
  aggressive steps. They are gated behind the single confirmation prompt and listed in the audit before
  you confirm; use `-SkipCBS` / `-SkipServices` to opt out.
- Disabling services uses `Start=4` (reversible) rather than `sc delete`, so a service can be re-enabled
  if needed.
- A **restart** is recommended after a removal run.
- As with any debloat tool, some third-party antivirus may flag the TrustedInstaller technique as a
  false positive. Test in a VM first if unsure.

---

## Credit

Built on top of [zoicware/RemoveWindowsAI](https://github.com/zoicware/RemoveWindowsAI)
(see `README.md`, `Documentation.md`, `OtherAIFeatures.md` in this folder). This script reuses its
TrustedInstaller engine and AI inventory, then re-shapes the policy around a *keep-the-runtime*
foundation mode and a re-runnable audit.
