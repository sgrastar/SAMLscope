"""Stop a selected campaign before preparing unrelated actions after its case terminates.

The public campaign classification exposes the actual stored CaseOutcome.  It does not
turn an unresolved NOT_VERIFIED into a resolved finding or restart a terminal case.
"""

OUTCOMES = {
    'SATISFIED', 'SATISFIED_WITH_NOTE', 'VIOLATED', 'INDETERMINATE',
    'INCONSISTENT', 'NOT_VERIFIED',
}


def require_unfinished(report, run_id, case_id):
    if not isinstance(report, dict) or report.get('runId') != run_id:
        raise ValueError('Selected campaign Run is missing or different')
    rows = report.get('classifications')
    if not isinstance(rows, list):
        raise ValueError('Selected campaign classifications are missing')
    selected = [row for row in rows if isinstance(row, dict) and row.get('caseId') == case_id]
    if len(selected) != 1 or 'outcome' not in selected[0]:
        raise ValueError('Selected native case classification is missing or ambiguous')
    outcome = selected[0]['outcome']
    if outcome is None:
        return
    if not isinstance(outcome, str) or outcome not in OUTCOMES:
        raise ValueError('Selected native case outcome is unknown')
    raise ValueError('Selected native case already finished (' + outcome
                     + '); no unrelated action is prepared or sent')
