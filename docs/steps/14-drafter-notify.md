# Step 14 — The drafter's notice: decline and undeliverable

Status: **implemented** (migration v6, `notify_email`, two new mail kinds, the
worker hook, the CLI flag). §5 is manual acceptance against the live instance.

## 1. The problem

Every message this service sends went to a party. Invite, reminder,
cancellation — the drafter, the person who asked for the signature and who owns
the outcome, had no address anywhere. `envelopes.created_by` records which admin
or user row created the envelope, but no query joins a user row to an email
address, and a machine client has no user row at all.

So the two outcomes a drafter most needs to know about were silent:

- **A party declined.** The envelope closes, every link in it stops working, and
  the only trace is an event row nobody reads.
- **An invitation never arrived.** After `signmail.MaxAttempts` the row is marked
  given-up and an event is raised. From the outside the envelope sits in `sent`
  forever, and the queue depth is the only way to notice.

Both are recoverable by the drafter (send a new request, or fix the address) and
neither is recoverable by the service.

## 2. The shape

`envelopes.notify_email`, optional, normalised at the same layer that normalises
party addresses, and validated with the same parser. Set it on create:
`pdf-go envelope create -notify "Ann <ann@corp.test>"`. Empty means "tell
nobody", which is the default and must stay the default — an envelope whose
drafter has no address is a normal case, not an error.

Two new mail kinds, `declined` and `undeliverable`, both addressed to the
drafter rather than to a party. `mail_queue` grows two columns for that:

- `recipient` — the address the row will be sent to. Party-addressed rows leave
  it null and keep reading the party row, so no existing code changes behaviour;
  a drafter notice writes it at enqueue time because the party row is not the
  recipient.
- `detail` — the free text the notice quotes: the party's stated reason, or the
  transport's rejection.

## 3. Rules, and why each one exists

- **A drafter notice carries no link.** A declined request closes every link in
  the envelope and an undeliverable one never reached anyone who could use it.
  Printing a link would hand out a URL that answers 410. `Render` refuses the
  combination instead of silently dropping it (`noLinkKinds`).
- **A failed notice is not an error.** A party's decline that commits but whose
  notice cannot be queued is still a decline. Returning the notice failure would
  tell the party "your decline failed" when it did not. The failure lands as an
  event; the decline result reports `notified: false`.
- **A notice that gives up raises no notice.** Two rows describing each other's
  failure is a loop, and against a dead relay it is a queue that never empties.
  Only `KindInvite` earns the undeliverable notice.
- **The transport's rejection is carried through.** "Your mail did not arrive" is
  worth less than the remote box's answer: `550 5.1.1 unknown user` tells the
  drafter the address is wrong; "it failed" tells them nothing.
- **A reminder does not earn a notice.** The party may have the original invite
  and simply not have used it yet. A reminder giving up is a symptom, not a
  finding. This is also why the mailing button queues kind `invite` and not
  `reminder`: the second copy of a link is sent precisely because the first one
  may never have arrived, and a message sent for that reason deserves the notice
  if it bounces.

## 4. Tests

- `internal/signstore/store_test.go` — the two new columns round-trip; a
  party-addressed row still resolves its recipient through the party row.
- `internal/signmail/drafter_test.go` — both templates render, refuse a link, and
  strip markup out of a hostile reason and a hostile address.
- `internal/signflow/notify_test.go` — the decline reaches the drafter's mailbox
  and not the party's; no `notify_email` means no row and no error; an invite
  that gives up raises one notice per party; an undeliverable notice that itself
  gives up raises none; a reminder that gives up raises none.
- `internal/signflow/consent_test.go` — the decline result reports the notice.

Two findings during this step, both from the render rules rather than the code:
the "link must appear in full" rule wrongly required a link in a message whose
whole point is that there is no link, and the markup test's `<` assertion caught
an email address rather than markup. Both assertions were wrong; the rule and the
code were right.

## 5. Manual acceptance

`scripts/drafter-notify-live.sh` drives the live instance: create with
`-notify`, claim, decline, then read `mail_queue` for the `declined` row and the
outbox/log for the send. Against the production instance the drafter received the
decline notice at the configured address, quoting the party's reason.

```
sh scripts/prod-sign-run.sh                 # the full walk, idempotent
sh scripts/drafter-notify-live.sh           # the drafter's notices, same instance
```

## Signoff

- [x] migration v6 applies to an existing database (verified on `tmp/real/signsrv.db`)
- [x] an envelope with no `notify_email` behaves exactly as before
- [x] a party's decline does not fail when the notice cannot be queued
- [x] the drafter received both notice kinds on the live instance
- [x] `gofmt -l`, `go vet`, `go test` silent across all packages
