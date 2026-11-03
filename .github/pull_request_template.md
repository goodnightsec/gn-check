## What

<!-- What this pull request changes, in one or two sentences. One purpose per pull request. -->

## Why

Closes <!-- #N. Planned work is linked from its issue instead, and is not named here. If there is no issue, say why the change is needed. -->

## How verified

<!-- Commands run and their result, before and after. A behavior change has a test, or say why there is none. -->

- [ ] `gofmt -l .` clean, `go vet ./...`, `go build ./...`
- [ ] `go test ./...` — and `go test -race -count=1 ./...` with `NSC_TEST_DATABASE_URL` set (what CI runs) if the change touches store/DB or concurrency paths
- [ ] `cd web && npm run build` (if the SPA changed)
- [ ] Behavior checked against the running stack / browser (if user-visible)

## Dependencies and security

<!-- New direct dependencies: why, license, maintained? Added or changed dependencies with a high or critical advisory, and why they are accepted. Changes to CI or automation. Invariant or docs impact, migration (new numbered file / repair-forward) notes, follow-ups intentionally skipped. Anything a reviewer must look at closely. Write "None" if nothing applies. -->

Depends on: <!-- other open pull requests or issues, or delete this line -->
