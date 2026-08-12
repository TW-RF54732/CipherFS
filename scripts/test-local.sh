#!/usr/bin/env bash
set -euo pipefail

scope=Auto
level=Fast
base_ref=
dry_run=0
while (($#)); do
  case "$1" in
    --scope) scope="$2"; shift 2 ;;
    --level) level="$2"; shift 2 ;;
    --base-ref) base_ref="$2"; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    *) echo "usage: $0 [--scope Auto|Shell|Cli|Core|Update|WinFsp|Fuse|All] [--level Fast|Runtime|Full] [--base-ref REF] [--dry-run]" >&2; exit 2 ;;
  esac
done

case "$scope" in Auto|Shell|Cli|Core|Update|WinFsp|Fuse|All) ;; *) echo "invalid scope: $scope" >&2; exit 2 ;; esac
case "$level" in Fast|Runtime|Full) ;; *) echo "invalid level: $level" >&2; exit 2 ;; esac

script_dir=${BASH_SOURCE[0]%/*}
[[ "$script_dir" == "${BASH_SOURCE[0]}" ]] && script_dir=.
cd "$script_dir/.."
run() { printf '> '; printf '%q ' "$@"; printf '\n'; ((dry_run)) || "$@"; }

declare -A selected=()
if [[ "$scope" == Auto ]]; then
  if [[ -z "$base_ref" ]]; then
    if git rev-parse --verify origin/main >/dev/null 2>&1; then base_ref=origin/main; else base_ref=HEAD~1; fi
  fi
  mapfile -t files < <({ git diff --name-only "$(git merge-base HEAD "$base_ref")...HEAD"; git diff --name-only; git diff --cached --name-only; git ls-files --others --exclude-standard; } | sort -u)
  code=0
  for file in "${files[@]}"; do
    [[ "$file" == *.md || "$file" =~ ^(README|ARCHITECTURE|TESTING|RELEASING|THIRD_PARTY|release_notes/) ]] && continue
    code=1
    case "$file" in
      apps/cipherfs-windows-shell/*) selected[Shell]=1 ;;
      apps/cipherfs-cli/*) selected[Cli]=1 ;;
      crates/cipherfs-core/*) selected[Core]=1 ;;
      crates/cipherfs-update/*) selected[Update]=1 ;;
      crates/cipherfs-winfsp/*) selected[WinFsp]=1 ;;
      crates/cipherfs-fuse/*) selected[Fuse]=1 ;;
      *) selected[All]=1 ;;
    esac
  done
  ((code)) || selected[Docs]=1
else
  selected[$scope]=1
fi
[[ -n "${selected[All]:-}" ]] && selected=([All]=1)
echo "Selected scope: ${!selected[*]}; level: $level"
run cargo fmt --all -- --check
run git diff --check
[[ -n "${selected[Docs]:-}" ]] && exit 0

declare -A packages=()
add() { for package in "$@"; do packages[$package]=1; done; }
for item in "${!selected[@]}"; do
  case "$item" in
    Shell) add cipherfs-windows-shell ;;
    Cli) add cipherfs-cli ;;
    Core) add cipherfs-core cipherfs-cli cipherfs-fuse ;;
    Update) add cipherfs-update cipherfs-cli ;;
    WinFsp) echo 'WinFsp scope is Windows-only; run scripts/test-local.ps1.' >&2 ;;
    Fuse) add cipherfs-fuse cipherfs-cli ;;
    All) add cipherfs-core cipherfs-update cipherfs-cli cipherfs-fuse ;;
  esac
done
for package in "${!packages[@]}"; do
  run cargo test --locked -p "$package"
  run cargo clippy --locked -p "$package" --all-targets -- -D warnings
done

if [[ "$level" == Runtime || "$level" == Full ]]; then
  if [[ -n "${packages[cipherfs-cli]:-}" || -n "${packages[cipherfs-fuse]:-}" ]]; then
    run cargo build --locked --release --target x86_64-unknown-linux-musl -p cipherfs-cli
    case_dir="${TMPDIR:-/tmp}/cipherfs-local-e2e-$$"
    mkdir -p "$case_dir/source/empty" "$case_dir/mount" "$case_dir/corrupt-mount"
    printf 'local runtime smoke\n' > "$case_dir/source/secret.txt"
    head -c 4194321 /dev/urandom > "$case_dir/source/boundary.bin"
    run expect tests/linux_e2e.exp ./target/x86_64-unknown-linux-musl/release/cipherfs "$case_dir"
  fi
fi
if [[ "$level" == Full ]]; then
  run cargo check --locked --workspace --all-targets
  run cargo clippy --locked --workspace --all-targets -- -D warnings
  run cargo test --locked --workspace
  run cargo audit --ignore RUSTSEC-2024-0436
  run cargo deny --locked check advisories licenses sources
fi
