# Contributor Guidelines

## Formatting
- Run `cargo fmt` before committing.
- If rustfmt fails to install or run, note it in the PR.

## Build checks
- Run `cargo check` to verify the project builds.
- If the command fails, note the error in the PR.

## Network Issues
Internet connectivity is only available during the setup phase of the
environment. If additional dependencies are required, make sure they are added
to `Cargo.toml` before the environment starts so they can be fetched while
networking is still enabled.

## Git
- Use a single commit per change with a clear message.
- Show `git status --short` in the PR testing section.

## Pull Request Template
Provide a summary of changes and the output of the required commands under a **Testing** section.


## For Gemeni AI coding assistant

### When I ask you to "finalize PR"
Make sure the last time we ran our test, they succeeded. Make sure our main branch is up to date. If not on a feature branch already, branch off main, name it feature/something-meaningful-but-short. Add all the relevant files via `git add`. Write a multiline commit message using the workaround below. git commit, git push.

**Future Self/AI Note: Handling Multi-Line Git Commits**

**Problem:** The `run_terminal_cmd` tool's `command` argument is strict and does not permit newline characters, preventing direct multi-line `git commit -m "..."` messages.

**Solution/Workaround:**
1.  **Draft the multi-line commit message.**
2.  **Use `edit_file` tool:** Write the full, multi-line commit message to a temporary file (e.g., `target/COMMIT_MSG.tmp` or a similar path covered by gitignore).
3.  **Use `run_terminal_cmd` tool:** Execute `git add . && git commit -F path/to/your/COMMIT_MSG.tmp && rm path/to/your/COMMIT_MSG.tmp`.

This approach successfully applies detailed, multi-line commit messages while adhering to tool limitations. Remember to clean up the temporary commit message file if necessary (though often `.gitignore` would cover `target/`).