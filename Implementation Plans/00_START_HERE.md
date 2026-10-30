# SecureCheck — Implementation Plan (Start Here)

**Project:** SecureCheck: An Endpoint Security Audit Tool for Checking Computer Security Settings and Recommending Fixes
**Course:** IT23/L System Administration and Maintenance — Project #9
**Developer:** Evander Harold S. Amorcillo
**AI IDE:** Google Antigravity

## Files in this plan
| File | Who | What |
|---|---|---|
| `Phase_0_Lab_Setup_YOU.md` | You | Laptop tools, 2 test VMs, remote PowerShell |
| `PROJECT_BRIEF.md` | Antigravity reads it every phase | Tech stack, database, 16 checks, scoring, roles, colors, rules |
| `Phase_1_Setup_Login_Roles.md` | Antigravity | Project setup, database, login, roles, layout |
| `Phase_2_Data_Model_Admin_Pages.md` | Antigravity | Tables + Computers, Users, Checklist, Settings pages |
| `Phase_3_PowerShell_Audit_Script.md` | Antigravity | The script that collects the security settings |
| `Phase_4_PowerShell_Runner.md` | Antigravity | C# runs the script remotely + Test Connection |
| `Phase_5_Evaluation_Engine.md` | Antigravity | Pass/Fail, risk levels, score + unit tests |
| `Phase_6_Running_Audits.md` | Antigravity | Run Audit page, live progress, saving results, alerts |
| `Phase_7_Dashboard_Results.md` | Antigravity | Dashboard, results, fix steps, history, alerts page |
| `Phase_8_Reports.md` | Antigravity | PDF and CSV reports |
| `Phase_9_Security_Polish_Demo.md` | Antigravity + You | Security check, polish, lab scripts, README, demo |

## How to use with Antigravity
1. Do **Phase 0** yourself first.
2. Create an empty folder (e.g. `C:\Projects\SecureCheck`) and open it in Antigravity.
3. Copy `PROJECT_BRIEF.md` into the project as `docs/PROJECT_BRIEF.md`. Optional: also add its **"Rules for the AI IDE"** section as a workspace rule in Antigravity's Customizations, so the agent always follows it.
4. Copy your logo to `src/SecureCheck.Web/wwwroot/img/logo.png` after Phase 1 creates the folder.
5. Use **Planning mode** (not Fast) and paste **one phase file at a time**. Read the plan the agent shows you before letting it build.
6. After each phase, go through its **Done when** checklist yourself. If something fails, paste the error back to the agent and fix it before moving on.
7. Commit to Git after each phase that passes: `git commit -m "Phase 3: audit script"`. If a phase goes badly, you can go back to the last commit.
8. Start a **new conversation** in Antigravity for each phase. A fresh chat plus the brief keeps the agent from mixing things up.
9. If you switch models later (e.g. to a different Gemini model), nothing changes — the brief keeps everything consistent.

## Suggested schedule (presentation ~2nd week of December)
| Week | Dates | Phases |
|---|---|---|
| 1 | Oct 30 – Nov 5 | Phase 0, Phase 1 |
| 2 | Nov 6 – Nov 12 | Phase 2, Phase 3 |
| 3 | Nov 13 – Nov 19 | Phase 4, Phase 5 |
| 4 | Nov 20 – Nov 26 | Phase 6 |
| 5 | Nov 27 – Dec 3 | Phase 7, Phase 8 |
| 6 | Dec 4 – Dec 10 | Phase 9, practice the demo, screenshots |

This leaves about 1 week of extra time for problems. Phase 4 (remote PowerShell) is the most likely to give errors, so don't fall behind before it.

## If you run out of time, cut these first
- Diagnostics page (Phase 4) and Activity Log page (Phase 9)
- Computer History chart (Phase 7)
- CSV export (Phase 8) — keep the PDF
- User guide (Phase 9) — keep the README

**Do not cut:** the 16 checks, risk levels and score, fix steps, compare with previous audit, alerts, roles, and the PDF report. These are all promised in your proposal.

## Safety note
`lab/Make-WeakPC.ps1` (Phase 9) weakens a computer's security on purpose for the demo. Run it **only on the test VM**, never on your laptop. If Antigravity asks to run it in its terminal, say no.
