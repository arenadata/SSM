## Code Review Checklist

- [ ] Code follows Java conventions: meaningful naming, static strings extracted to constants, no duplication (shared methods/utilities extracted)
- [ ] Methods are compact and do one thing; blank lines are used only when formatting cannot be achieved otherwise
- [ ] Stability and isolation: Tests are independent of execution order; no direct database access when an API exists; resources are properly closed
- [ ] Explicit waits (Selenide waits) and awaitility are used instead of `Thread.sleep`; timeouts are extracted to constants/config
- [ ] Assertions verify a specific business expectation with an informative message; key steps are logged
- [ ] When using code that violates the agreements, minimal refactoring is done within the MR; if the volume is large, a separate task is created in the tracker
- [ ] TmsLink has been added for each new test. If no test cases, @Link can be added with link to user story
- [ ] spotless:apply task has been executed before push
- [ ] The MR is requested for review in `internal-java-qa` with tagging responsible person