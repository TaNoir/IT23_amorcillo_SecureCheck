> **Paste this whole file into Antigravity (Planning mode).**
> Read `docs/PROJECT_BRIEF.md` first and follow it exactly. Do only this phase — do not start the next one.
> Before writing code, show me your plan for this phase. When finished, list the files you created or changed, run `dotnet build`, and tell me how to test this phase.

## Phase 5 — Evaluation engine and unit tests

**Goal:** Turn the raw JSON into Pass/Fail/Error results for each enabled check, plus a score and overall risk. Fully unit tested.

**Tasks**
1. C# classes that match the JSON contract (`AuditFacts` and nested classes), deserialized with `System.Text.Json` (case-insensitive, allow nulls).
2. `AuditEvaluator` service:
   `EvaluationResult Evaluate(AuditFacts facts, IReadOnlyList<CheckDefinition> enabledChecks, DateTimeOffset now)`
   - One rule per check `Code` (use a `switch` or a dictionary of small functions — keep it readable).
   - Each rule returns `Status`, `ActualValue` (e.g. "Off", "45 days ago", "3 admins"), `ExpectedValue` (e.g. "On", "≤ 30 days", "≤ 2 admins"), and `Message`.
   - If the needed section/sub-part has an `error` or the value is null → `Status = Error` with that message.
   - Unknown `Code` → `Skipped`.
   - Uses `Threshold` from the CheckDefinition (not hard-coded numbers).
   - Implements the brief's **Scoring rules** exactly (score, overall risk, counts).
3. `EvaluationResult { List<CheckOutcome> Outcomes, int? Score, RiskLevel? OverallRisk, int Passed, int Failed, int Errors }`.
4. Unit tests (xUnit) using the 3 fixtures and a fixed `now`:
   - `secure-pc.json` → all Pass, score 100, overall risk null.
   - `weak-pc.json` → expected failures (FW-PUBLIC, ACC-GUEST, SVC-SMB1, SVC-TELNET, ACC-PWLENGTH, ACC-PWCOMPLEX, ACC-LOCKOUT, UPD-RECENT), overall risk Critical, score matches a hand calculation written in the test comment.
   - `partial-error.json` → AV checks are Error and are excluded from the score.
   - Threshold change test: UPD-RECENT with threshold 90 passes for a 45-day-old update; with 30 it fails.
   - Disabled check is not evaluated.
   - Score is null when every check is Error.

**Done when**
- [ ] `dotnet test` passes all tests.
- [ ] Running the evaluator on the real JSON from the Diagnostics page gives sensible results (add a "Evaluate" button there that shows the result table).
