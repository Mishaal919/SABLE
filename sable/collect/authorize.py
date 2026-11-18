"""CL-04: authorisation prompt shown before any SSH connection is opened.

The collector must call :func:`confirm_authorisation` and stop if it returns False,
*before* constructing an SSH client. ``assume_yes`` (wired to ``--yes``) skips the
prompt for CI; ``prompt`` is injectable so tests never block on real input.
"""
PROMPT = 'Are you authorised to assess this host? [y/N] '


def confirm_authorisation(assume_yes=False, prompt=input):
    """Return True only if the operator explicitly authorises the scan."""
    if assume_yes:
        return True
    try:
        answer = prompt(PROMPT)
    except EOFError:
        return False
    return str(answer).strip().lower() in ('y', 'yes')
