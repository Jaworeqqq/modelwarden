# Expense reports: what finance needs

This article is the false-positive guard for the corpus scanner. It is written the
way a real internal knowledge-base article is written, including the things that a
naive rule would report: it addresses the reader as "you", it quotes a system
message, it explains a URL parameter, and it repeats its own subject throughout.

## Who can approve

You must submit a report within 30 days of the expense. Your manager approves
anything under 500 EUR; above that, the finance team approves it as well. If an
expense is missing a receipt, the approver should reject it and the system will
notify you by email.

## Filing a report

1. Open the expenses portal and choose **New report**.
2. Attach the receipt as a PDF or a photograph.
3. Pick the cost centre. When in doubt, use the one on your last approved report.

The portal rejects an upload larger than 10 MB. If that happens, reduce the
resolution of the photograph rather than splitting the receipt across two files,
because the approver needs to see the total on the same page as the date.

## Reading the status page

The status endpoint takes a query string, so `?status=pending&owner=me` filters
the list down to what is waiting on you. Add `&sort=date` to see the oldest first.
This is ordinary documentation about a URL and must not be reported as anything else.

## When a report is rejected

A rejected report shows the approver's reason at the top. The most common one is
an unreadable receipt. Fix the attachment and submit the same report again instead
of creating a second one, otherwise finance sees two claims for one expense.

Do not tell a supplier that a payment has been approved before it appears in the
ledger — the approval and the payment are separate steps, and suppliers plan
around the second one.

## Where the rules come from

The travel and expense policy is the authoritative document for limits; this
article only explains the process around it. Limits change every January, so check
the policy rather than trusting the numbers quoted in older articles.
