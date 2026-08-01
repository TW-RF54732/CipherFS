#!/usr/bin/env bash
set -euo pipefail

binary=${CIPHERFS_BENCH_BINARY:-./target/release/cipherfs}
size_mib=${1:-1024}
runs=${2:-3}
read -r -a thread_counts <<< "${CIPHERFS_BENCH_THREADS:-1 0}"

if [[ ! -x "$binary" ]]; then
    echo "Benchmark binary is not executable: $binary" >&2
    exit 1
fi
if ! command -v script >/dev/null || [[ ! -x /usr/bin/time ]]; then
    echo "This benchmark requires util-linux script and /usr/bin/time." >&2
    exit 1
fi

bench_dir=$(mktemp -d /tmp/cipherfs-parallel-bench.XXXXXX)
case "$bench_dir" in
    /tmp/cipherfs-parallel-bench.*) ;;
    *) echo "Unexpected temporary path: $bench_dir" >&2; exit 1 ;;
esac
cleanup() {
    rm -rf -- "$bench_dir"
}
trap cleanup EXIT

mkdir "$bench_dir/source"
dd if=/dev/zero of="$bench_dir/source/data.bin" bs=1M count="$size_mib" status=none

run_with_input() {
    local input=$1
    local timing=$2
    shift 2
    local command
    printf -v command '%q ' "$@"
    printf '%b' "$input" | /usr/bin/time -f '%e %U %S' -o "$timing" \
        script -qec "$command" /dev/null >/dev/null
}

printf 'cores=%s size_mib=%s runs=%s\n' "$(nproc)" "$size_mib" "$runs"
for threads in "${thread_counts[@]}"; do
    for run in $(seq 1 "$runs"); do
        container="$bench_dir/vault-${threads}-${run}.cfs"
        extracted="$bench_dir/extracted-${threads}-${run}"

        timing="$bench_dir/pack-${threads}-${run}.txt"
        run_with_input 'benchmark-password\nbenchmark-password\n\n' "$timing" \
            "$binary" pack "$bench_dir/source" "$container" --threads "$threads" \
            --m-cost 8192 --t-cost 1 --p-cost 1
        read -r elapsed user system < "$timing"
        printf 'operation=pack threads=%s run=%s elapsed=%s user=%s system=%s\n' \
            "$threads" "$run" "$elapsed" "$user" "$system"

        timing="$bench_dir/verify-${threads}-${run}.txt"
        run_with_input 'benchmark-password\n' "$timing" \
            "$binary" verify "$container" --threads "$threads"
        read -r elapsed user system < "$timing"
        printf 'operation=verify threads=%s run=%s elapsed=%s user=%s system=%s\n' \
            "$threads" "$run" "$elapsed" "$user" "$system"

        timing="$bench_dir/extract-${threads}-${run}.txt"
        run_with_input 'benchmark-password\n' "$timing" \
            "$binary" extract "$container" "$extracted" --threads "$threads"
        read -r elapsed user system < "$timing"
        printf 'operation=extract threads=%s run=%s elapsed=%s user=%s system=%s\n' \
            "$threads" "$run" "$elapsed" "$user" "$system"

        cmp "$bench_dir/source/data.bin" "$extracted/data.bin"
        rm -rf -- "$extracted"
        rm -f -- "$container"
    done
done
