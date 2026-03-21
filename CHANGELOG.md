# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic Versioning.

## [0.0.2] - 2026-03-21

### Added

- A documented release workflow that validates the crate on Linux, macOS, and Windows before publishing to crates.io.
- A GitHub release pipeline that verifies the tag matches `Cargo.toml`, uploads the packaged crate artifact, and creates a release.
- Targeted unit tests covering Unix and Windows privilege mapping edge cases.
- A changelog-backed release note source for GitHub releases.

### Changed

- Updated direct dependencies to current crate releases used by the project.
- Expanded CI to run build, test, clippy, and formatting checks across Linux, macOS, and Windows.
- Bumped the crate version to `0.0.2`.

### Fixed

- Fixed the Windows compile failure caused by calling `window::check_main::is_app_elevated()` even though `check_main` was a function, not a module.
- Corrected Unix privilege detection so processes running with effective UID `0` are treated as elevated, which covers `sudo` and setuid-root cases.
- Removed the unused `log` dependency and cleaned up warning-producing test code.

Full Changelog: https://github.com/spa5k/is_sudo/compare/v0.0.1...v0.0.2
