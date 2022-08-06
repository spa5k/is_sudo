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
