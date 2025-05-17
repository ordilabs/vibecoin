# Contributor Guidelines

## Formatting
- Run `cargo fmt` before committing.
- If rustfmt fails to install or run, note it in the PR.

## Build checks
- Run `cargo check` to verify the project builds.
- If the command fails, note the error in the PR.

## Network Issues
Currently the container lacks network access. Skip `cargo fmt` and `cargo check`
commands while this issue persists. Mention the lack of networking in your PR.

Internet connectivity is only available during the setup phase of the
environment. If additional dependencies are required, make sure they are added
to `Cargo.toml` before the environment starts so they can be fetched while
networking is still enabled.

## Git
- Use a single commit per change with a clear message.
- Show `git status --short` in the PR testing section.

## Pull Request Template
Provide a summary of changes and the output of the required commands under a **Testing** section.
