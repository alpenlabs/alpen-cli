//! Shared metadata for the Alpen CLI.

#![expect(
    unused_crate_dependencies,
    reason = "package dependencies are used by the binary target"
)]

/// Name of the executable installed by this package.
///
/// # Examples
///
/// ```
/// assert_eq!(alpen_cli::BINARY_NAME, "alpen");
/// ```
pub const BINARY_NAME: &str = "alpen";
