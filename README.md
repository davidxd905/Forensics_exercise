# DF-017 login and file activity investigation

**All records, accounts, hosts, addresses and file paths are invented. The referenced files themselves are not supplied.**

## Case brief

A training evidence portal recorded repeated login failures and file-access
events on 20 October 2026. Determine which successful sessions meet the stated
rule and what subsequent downloads are recorded. Prioritise a session for
review without assuming an intrusion or attributing activity to a person.

The exports are deliberately unsorted and contain duplicate and malformed
records. Their timestamps use Z and +01:00 offsets. Assume both sources use
the same session-ID namespace. Clock accuracy, log completeness and the
real-world identity behind an account have not been independently established.

## Run from this folder

Python 3.10 or newer, standard library only. No notebook, pip install or API key.

| Purpose | macOS or Linux | Windows PowerShell |
| --- | --- | --- |
| Run starter or full analysis | `python3 analyze_case.py` | `py analyze_case.py` |
| Run login stage only | `python3 analyze_case.py --stage logins` | `py analyze_case.py --stage logins` |
| Check function 1 | `python3 check_solution.py LoginChecks` | `py check_solution.py LoginChecks` |
| Check function 2 | `python3 check_solution.py DownloadChecks` | `py check_solution.py DownloadChecks` |
| Run all checks | `python3 check_solution.py` | `py check_solution.py` |

If Windows does not recognise `py`, use `python` after checking that
`python --version` reports Python 3.10 or newer. Otherwise install Python 3.

Implement only `find_login_sequences` and `correlate_downloads` in
`analyze_case.py`. Their docstrings are the exact contracts. The supplied
loader, evidence, manifest and tests remain unchanged.

## Rules and field meanings

1. For every SUCCESS at T, group on `(username, source_ip, host)` and count
   FAIL events where **T - 5 minutes <= time < T**. Flag at least three.
   Each success is evaluated independently; earlier successes do not reset
   the window. A failure may support more than one alert.
2. Join file events using **username AND host AND session_id**. Keep only
   `action == "DOWNLOAD"`, `result == "SUCCESS"`, and **T <= time <= T + 10 minutes**.
   Count events, even if their paths repeat. Sum their integer bytes values.
   Retain alerts with zero matches. Sort by descending byte total, then time
   and success event ID. This ranking measures recorded volume, not guilt.
3. `event_id` identifies one event within its source. `session_id` links the
   two sources. `bytes` is the transfer size recorded by the application;
   independent transfer completion and destination evidence are not supplied.

## Evidence handling supplied for you

`evidence_tools.py` verifies the original CSV byte hashes against
`evidence_manifest.json`, trims outer whitespace, validates rows, requires
explicit timezone offsets, converts times to UTC and byte strings to integers,
and removes identical repeated event IDs. It records duplicate and rejected
CSV row numbers in `audit.json`. Conflicting versions of an ID stop analysis.
Rejected rows remain in the source; they are excluded from computed findings.

The starter writes `audit.json` before stopping at the first TODO. Function 1
adds `login_alerts.json`; the completed program adds `summary.json`. Rerun after
every change: old output files can be stale. A hash match demonstrates agreement
with this supplied baseline; it does not establish authenticity or completeness.
`.gitattributes` preserves CSV bytes through Git on all operating systems.

## Verified results -- complete this section

| Source | Data rows excluding header | Accepted unique | Duplicate | Rejected |
| --- | --- | --- | --- | --- |
| auth_log.csv | 60 | 54 | 1 | 5 |
| file_log.csv | 35 | 30 | 1 | 4 |

- SHA-256 check outcome and what it establishes: [Both CSV files passed the SHA-256 check.]
- One rejected event ID and the exact rejection reason: [F901 – bytes must be nonnegative]
- Number of flagged successful sessions: [3]

| Success ID | Account | Session | Supporting failure IDs | Download IDs | Event count | Total bytes |
|---|---|---|---|---|---:|---:|
| A005 | analyst01 | S-104 | A002, A003, A004 | F001, F002, F003 | 3 | 5509120 |
| A018 | analyst02 | S-304 | A015, A016, A017 | F013 | 1 | 2048 |
| A014 | backup_svc | S-204 | A011, A012, A013 | None | 0 | 0 |

## Manual evidence check -- do this without asking AI to count for you

For the highest-volume flagged session, find every supporting failure, the
success and every qualifying download in the original CSV files. Record their
original timestamps and UTC equivalents. Add rows as needed.

| Source and event ID | Original timestamp | UTC timestamp | What the row records |
| --- | --- | --- | --- |
| auth_log.csv – A002 | 08:58:00Z | 08:58:00 | Failed login |
| auth_log.csv – A003 | 09:00:00Z | 09:00:00 | Failed login |
| auth_log.csv – A004 | 10:01:00+01:00 | 09:01:00 | Failed login |
| auth_log.csv – A005 | 09:03:00Z | 09:03:00 | Successful login |
| file_log.csv – F001 | 09:05:00Z | 09:05:00 | Successful download, 5242880 bytes |
| file_log.csv – F002 | 10:07:00+01:00 | 09:07:00 | Successful download, 262144 bytes |
| file_log.csv – F003 | 09:13:00Z | 09:13:00 | Successful download, 4096 bytes |

- Manual sum of download bytes, showing the addition: 5242880 + 262144 + 4096 = 5509120 bytes
- A001 versus A002: which qualifies for the A005 window and why? [A002 is included because it happened at 08:58, five minutes before A005. A001 happened one second too early and is therefore excluded.]
- F003 versus F004: which qualifies for the A005 follow-up and why? [F003 is included because it happened exactly ten minutes after A005. F004 happened one second later and is therefore excluded.]
- Why F005 is excluded even though the account matches: [F005 is excluded because it has a different session ID, even though the username matches.]
- One +01:00 timestamp and its equivalent UTC time: [F002: 10:07:00 +01:00 is 09:07:00 UTC.]
- One limitation of excluding malformed records: [Some relevant events might be missing because malformed records are excluded from the analysis.]

## Checks actually run

Command, date and actual final result (paste output, including failures if any):

```text
[py check_solution.py LoginChecks – 9 tests passed.
py check_solution.py DownloadChecks – 7 tests passed.
py check_solution.py – 21 tests passed.]
```

All 21 supplied checks should pass. Passing these checks is limited validation
of the stated classroom rule, not certification of a forensic tool.

## AI interpretation and our final finding

Prompt 3 response about the overstated claim (keep the actual response):

The largest download total does not identify an attacker. The logs show recorded successful downloads, but they do not prove who performed them, whether they were authorized, or whether data was stolen. Matching hashes only show that the supplied CSV files match the provided baseline. They do not prove that the original logs are authentic or complete.

A more accurate conclusion is that session S-104, associated with analyst01, recorded three successful downloads totalling 5,509,120 bytes after login A005. This session should be reviewed, but the available logs do not establish who performed the downloads or whether the activity was unauthorized.

One claim we corrected or independently verified, with event IDs:

[I checked F003 and F004 in file_log.csv. F003 is included, but F004 is one second too late.]

Final 180-220 word finding, reviewed and edited by the pair:

[Session S-104 should be reviewed first. Three failed login attempts (A002, A003 and A004) were followed by a success login at 09:03 UTC (A005). After that three successful downloads were complet F001, F002 and F003. They total 5509120 bytes between 09:05 and 09:13 UTC.

Compared with S-104, session S-304 had one successful download of 2048 bytes (F013), following login A018. Session S-204 had no matching successful downloads after login A014. S-104 is therefore the highest priority based on recorded download volume. This does not prove that the activity was unauthorized or that files were stolen.

There are limitations some log records were rejected because of malformed data. The logs also do not contain file contents or identify who performed the downloads. A possible benign explanation is that the downloads were part of normal authorized work.

Further investigation should request the portals access and authorization records for session S-104. Network logs should also be requested to establish where the downloaded files went. These records could help determine whether the activity was expected or requires further investigation.]

It must cite evidence IDs, separate observation from inference, include a
comparison session, two limitations, one benign explanation and two next
evidence requests. Do not claim that an account or IP identifies a person.

## AI use and pair review

- Names of both partners: [David Thornberg & William Mattsson]
- GenAI tool/ChatGPT date and displayed model: [Chatgpt 2026, GPT-6]
- Prompts used and what they produced: [Prompt 1: Generated a Python function to find successful logins after repeated failed attempts. Prompt 2: Generated a Python function to match successful logins with successful downloads. Prompt 3: Reviewed an overstated claim about the attacker, stolen evidence and matching hashes. Prompt 4: Drafted a forensic finding based on the supplied evidence.]
- One follow-up question or correction, with a short response excerpt: [One followup question was about the python function that did not work at first.]
- Results of code and evidence checks performed: [LoginChecks: 9 tests passed. DownloadChecks: 7 tests passed. Full test suite: 21 tests passed. The CSV hashes matched the supplied manifest. Also manually checked the event IDs and timestamps in the original CSV files.]


## Submit

Submit one public repository URL per pair through the course route. Include the ten
starter project files and the newly generated `audit.json`, `login_alerts.json`,
and `summary.json`. Complete this README. The repository needs a starting
commit and a finished commit. The accompanying student guide gives the
90-minute schedule; `GitHub_CLI_Guide.docx` covers setup and upload.
Only synthetic exercise files belong in this repository. Keep credentials out.

Optional stretch after the core task: use the interactive Python console to
compare `min_failures=2` with `min_failures=3`, without changing the defaults or
original evidence. Which extra session appears, and does that change what you
can conclude? Record this separately from the required default output.
