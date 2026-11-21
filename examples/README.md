# Examples

`corp-example/` is the output of running the commands that `shaar example` prints, in order, on synthetic data for the made-up domain `corp.example`. Every name is invented.

| Folder | What it holds |
| --- | --- |
| `before/` | The exports and the column map the review starts from. |
| `campaign/` | The campaign: `campaign.json`, one packet per reviewer, and the report. |
| `returned/` | The packets as the reviewers sent them back. |
| `decisions/` | The decision record, the removals to make, and the report. |
| `after/` | Access read again after the due date. |
| `verification/` | The verification report. |

A test checks that these files are exactly what the code produces. To regenerate them after a deliberate change, run `uv run python -m tests.test_example`.
