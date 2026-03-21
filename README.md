# Is_sudo

## Checks if program is running as sudo in unix systems, or using admin permission in windows.

## Usage

```rust
use is_sudo::check;
use is_sudo::RunningAs;

fn main() {
    let running_as: RunningAs = is_sudo::check();

    match running_as {
        RunningAs::Root => println!("Running as root"),
        RunningAs::User => println!("Running as user"),
    }
}
```

## Release

Push a semver tag such as `v0.0.2` after updating `Cargo.toml`.

The GitHub release workflow will:

- run the test matrix on Linux, macOS, and Windows
- verify that the tag matches the crate version
- publish the crate to crates.io using `CARGO_REGISTRY_TOKEN`
- create a GitHub release and attach the packaged `.crate` file
