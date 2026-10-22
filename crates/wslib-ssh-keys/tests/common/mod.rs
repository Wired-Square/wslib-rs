#![allow(dead_code)]

// Made by `ssh-keygen`, with what `ssh-keygen -l` prints for each: the sk lines
// were assembled by hand around real public halves and checked the same way.
pub const ED25519: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA9frf+EPG/Tj073pmzcTZeK4yZ0Wf/NAWGM48zaq2HJ admin@bench";
pub const ED25519_FP: &str = "SHA256:/7MVDOe0auFFSFk/9EBpTvK7defzpFI3ccbS8WyAmiU";
pub const ECDSA: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIL/951t7/QxZnooRN8pNwr9bFDnSQIHq6yq4zimv5mmuDsZB/ioy69Wt5P1wh2ArNFOOtaTw08NvFaoMPtD66w= operator@bench";
pub const ECDSA_FP: &str = "SHA256:arVdHwn1I6i1kfUUJ3PCb73hKFaezbE76pxH2a5KVC8";
pub const ECDSA384: &str = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBNng7wSW3H8ChACdy8xBDlt6WoMnmAWDVMElNel3uLBNUgr+FJFuR2rcDKZqN93KtwjfPM5YBQhMioGYHkMnyEEL+a6XiStS3gDUadPPJdwBUgBDA1Apycs3eSKrpgGnsQ== p384@bench";
pub const ECDSA384_FP: &str = "SHA256:gFnJV5ld0oWwtMdrWGpuSTkT2rGeCx5S7bUfLyvpXQM";
pub const ECDSA521: &str = "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAD+J6W61FQ9uhyLxdWsYq1CkYl+PkxJnYT6ElBbEOL1y+jn/HLppOruoX2jiWQcP743jNB0IyGQ7O/B0HUJJtZd1AFyLbA3GnlQktYeqlLdAdCgfltfqvNTcvUZ9N2IwWlkRYbzx8Bh4G/mm2Kb/U7fUarFqFXrzOkOfsGTwoA+5DIlMQ== p521@bench";
pub const ECDSA521_FP: &str = "SHA256:oM/z0V46IlET/pgiNF/CiQQMagyKP7W7+3+MsV6vl/U";
pub const RSA: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCrEYcECnzrhxOETp/Kct+lhdhg8ZhGTE/NpIKU7zUgm8/bbV1uxz293xLB52wwGWqKiNEOJZ1z2iFnHsST1Lvlh2Kocd7AV1ooERRK2kJDEAjmCFyuG988YTXtJt+JUu3roThA+UG9TdP61h4ZmIjaUHZ3RJ2KMi7j0WhKsAoeF5nywSk2A5hsYadeGRxY/tQjmrw6VMbUjkzbN6bRELZoW3ILMOLQWvO7x9MSmnWWYrvwFWM00Pmu4tb9a6WsynAkwXuQftO5wCmA6kNFUAJeVZkAEaFcXAD59efZLzj7KBkDxROuy8kPkvE2vg8nFgCZZdSOv5hMjl9TaUQD0a5V admin@bench";
pub const RSA_FP: &str = "SHA256:JlvHCHo/qnlzFp2pjXSFpMLI3Zs4BZbxKvXnoHuKJm0";
pub const SK_ED25519: &str = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fAAAABHNzaDo= yubikey@bench";
pub const SK_ED25519_FP: &str = "SHA256:/p0CbeE3dk2SyW1OXXsThGc12ezDVD8eGw2/vtztDfk";
pub const SK_ECDSA: &str = "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBIL/951t7/QxZnooRN8pNwr9bFDnSQIHq6yq4zimv5mmuDsZB/ioy69Wt5P1wh2ArNFOOtaTw08NvFaoMPtD66wAAAAEc3NoOg== yubikey@bench";
pub const SK_ECDSA_FP: &str = "SHA256:f1UvroMzM8gxCd5M6avc28Rz0GgXGTcZxbrTRaZwl68";
