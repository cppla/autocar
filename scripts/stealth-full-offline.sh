#!/bin/sh
set -eu
umask 077

usage() {
	cat >&2 <<'EOF'
usage: scripts/stealth-full-offline.sh FULL_CAMPAIGN_DIR NEW_OUTPUT_DIR
       scripts/stealth-full-offline.sh self-test

Validate the complete 31,500-sample preregistered campaign plus ten browser
H2 controls, then extract and classify it in a pinned Docker image with no
network.  Exit zero means the evidence pipeline completed, not that the
superiority result passed; read audit.json and scores.json for that decision.
EOF
}

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd -P)
repo_root=$(CDPATH='' cd -- "$script_dir/.." && pwd -P)
helper="$script_dir/stealth-full-offline.py"

runtime_identity() {
	if [ "$1" -eq 0 ] || [ "$2" -eq 0 ]; then
		printf '0:0\n'
	else
		printf '%s:%s\n' "$1" "$2"
	fi
}

if [ "$#" -eq 1 ] && [ "$1" = self-test ]; then
	[ "$(runtime_identity 0 0)" = "0:0" ] || { echo "root identity self-test failed" >&2; exit 1; }
	[ "$(runtime_identity 501 20)" = "501:20" ] || { echo "non-root identity self-test failed" >&2; exit 1; }
	python3 "$helper" self-test
	exit 0
fi
[ "$#" -eq 2 ] || { usage; exit 2; }

invocation_dir=$(pwd -P)
campaign_dir=$1
output=$2
case "$campaign_dir" in /*) ;; *) campaign_dir="$invocation_dir/$campaign_dir" ;; esac
case "$output" in /*) ;; *) output="$invocation_dir/$output" ;; esac
case "$campaign_dir" in *','*) echo "FULL_CAMPAIGN_DIR must not contain a comma" >&2; exit 2 ;; esac
case "$output" in ''|/|*','*) echo "refusing unsafe NEW_OUTPUT_DIR" >&2; exit 2 ;; esac

dockerfile="$script_dir/stealth-offline.Dockerfile"
preregistration="$repo_root/testdata/stealth/preregistration.json"
docker_bin=${DOCKER_BIN:-docker}
for tool in "$docker_bin" dirname basename mkdir date id python3 git tar mktemp rm; do
	command -v "$tool" >/dev/null 2>&1 || { echo "required command not found: $tool" >&2; exit 2; }
done
[ -d "$campaign_dir" ] || { echo "full campaign directory not found: $campaign_dir" >&2; exit 2; }
[ -f "$dockerfile" ] || { echo "offline Dockerfile not found: $dockerfile" >&2; exit 2; }
[ -f "$helper" ] || { echo "offline audit helper not found: $helper" >&2; exit 2; }
[ -f "$preregistration" ] || { echo "preregistration not found: $preregistration" >&2; exit 2; }
campaign_dir=$(CDPATH='' cd -- "$campaign_dir" && pwd -P)

if [ -e "$output" ]; then
	echo "refusing to overwrite existing evidence path: $output" >&2
	exit 2
fi
output_parent=$(dirname "$output")
mkdir -p "$output_parent"
output_parent=$(CDPATH='' cd -- "$output_parent" && pwd -P)
output="$output_parent/$(basename "$output")"
case "$output/" in
	"$campaign_dir/"*) echo "NEW_OUTPUT_DIR must be outside FULL_CAMPAIGN_DIR" >&2; exit 2 ;;
	"$repo_root/"*) echo "NEW_OUTPUT_DIR must be outside the source repository" >&2; exit 2 ;;
esac
mkdir "$output"
output=$(CDPATH='' cd -- "$output" && pwd -P)

# Bind the formal analysis to the exact clean source tree frozen by capture.
# Runtime uses a Git-archive snapshot, so later host worktree changes cannot
# alter code or preregistration bytes observed by a running container.
python3 "$helper" repo-binding --repo "$repo_root" \
	--plan "$campaign_dir/plan.json" --phase before-build \
	--output "$output/repo-binding-before-build.json" \
	>"$output/repo-binding-before-build.stdout.json" \
	2>"$output/repo-binding-before-build.stderr.log"

repo_snapshot=$(mktemp -d /tmp/autocar-full-offline-repo.XXXXXX)
cleanup_snapshot() {
	case "$repo_snapshot" in
		/tmp/autocar-full-offline-repo.*) rm -rf -- "$repo_snapshot" ;;
	esac
}
trap cleanup_snapshot EXIT
trap 'exit 130' HUP INT TERM
git -C "$repo_root" archive --format=tar HEAD | tar -xf - -C "$repo_snapshot"
for required in \
	scripts/stealth-offline.Dockerfile scripts/stealth-full-offline.sh \
	scripts/stealth-full-offline.py scripts/stealth-features.py \
	scripts/stealth-classify.py testdata/stealth/preregistration.json
do
	[ -f "$repo_snapshot/$required" ] || { echo "Git snapshot lacks runtime tool: $required" >&2; exit 2; }
done
python3 "$repo_snapshot/scripts/stealth-full-offline.py" repo-binding \
	--repo "$repo_root" --plan "$campaign_dir/plan.json" --phase before-runtime \
	--runtime-repo "$repo_snapshot" \
	--output "$output/repo-binding-before-runtime.json" \
	>"$output/repo-binding-before-runtime.stdout.json" \
	2>"$output/repo-binding-before-runtime.stderr.log"

runtime_repo=$repo_snapshot
dockerfile="$runtime_repo/scripts/stealth-offline.Dockerfile"

docker_context=$($docker_bin context show)
docker_endpoint=$($docker_bin context inspect "$docker_context" --format '{{ (index .Endpoints "docker").Host }}')
case "$docker_endpoint" in
	unix://*|npipe://*) ;;
	*) echo "remote Docker contexts are refused: $docker_endpoint" >&2; exit 2 ;;
esac

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
run_id="full-offline-${timestamp}-$$"
image="autocar-stealth-offline:$run_id"
label="com.cppla.autocar.stealth-full-offline=$run_id"

# Image construction is the sole network-capable phase. Runtime phases below
# all use --network none; the Dockerfile pins the multi-architecture base
# manifest and both direct runtime packages.
$docker_bin build --pull=false --label "$label" \
	-f "$dockerfile" -t "$image" "$runtime_repo/scripts" \
	>"$output/image-build.log" 2>&1
image_id=$($docker_bin image inspect "$image" --format '{{.Id}}')

host_uid=$(id -u)
host_gid=$(id -g)
runtime_user=$(runtime_identity "$host_uid" "$host_gid")

run_offline() {
	$docker_bin run --rm --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --pids-limit 256 --memory 2g \
		--user "$runtime_user" --tmpfs /tmp:rw,nosuid,nodev,noexec,size=128m \
		-e PYTHONDONTWRITEBYTECODE=1 \
		--mount "type=bind,src=$campaign_dir,dst=/input,readonly" \
		--mount "type=bind,src=$runtime_repo,dst=/repo,readonly" \
		--mount "type=bind,src=$output,dst=/output" "$@"
}

run_offline --entrypoint /bin/sh "$image" -c \
	'python3 --version; tshark --version | sed -n "1,3p"; apk list --installed python3 tshark' \
	>"$output/toolchain.txt" 2>&1

set +e
run_offline "$image" python3 /repo/scripts/stealth-full-offline.py validate-input \
	--campaign-dir /input --preregistration /repo/testdata/stealth/preregistration.json \
	--output-dir /output \
	>"$output/validation.stdout.json" 2>"$output/validation.stderr.log"
validation_exit=$?

extraction_exit=not-run
classification_exit=not-run
if [ "$validation_exit" -eq 0 ]; then
	run_offline "$image" python3 /repo/scripts/stealth-features.py \
		--manifest /input/capture-manifest.csv \
		--output /output/features.csv --status-output /output/extraction.json \
		>"$output/extraction.stdout.json" 2>"$output/extraction.stderr.log"
	extraction_exit=$?
	if [ "$extraction_exit" -eq 0 ]; then
		run_offline "$image" python3 /repo/scripts/stealth-classify.py \
			--features /output/features.csv \
			--preregistration /repo/testdata/stealth/preregistration.json \
			--output /output/scores.json \
			>"$output/classification.stdout.json" 2>"$output/classification.stderr.log"
		classification_exit=$?
	fi
fi

python3 "$runtime_repo/scripts/stealth-full-offline.py" repo-binding \
	--repo "$repo_root" --plan "$campaign_dir/plan.json" --phase after-runtime \
	--runtime-repo "$runtime_repo" \
	--output "$output/repo-binding-after-runtime.json" \
	>"$output/repo-binding-after-runtime.stdout.json" \
	2>"$output/repo-binding-after-runtime.stderr.log"
repository_after_exit=$?

run_offline "$image" python3 /repo/scripts/stealth-full-offline.py audit \
	--campaign-dir /input --repo /repo --output-dir /output \
	--image-reference "$image" --image-id "$image_id" \
	--docker-endpoint "$docker_endpoint" --runtime-user "$runtime_user" \
	--validation-exit "$validation_exit" \
	--extraction-exit "$extraction_exit" --classification-exit "$classification_exit" \
	>"$output/audit.stdout.json" 2>"$output/audit.stderr.log"
audit_exit=$?
set -e

if [ "$repository_after_exit" -ne 0 ]; then
	echo "source repository drifted during offline processing; inspect $output/audit.json" >&2
	exit "$repository_after_exit"
fi
if [ "$audit_exit" -ne 0 ]; then
	echo "formal offline evidence pipeline failed; inspect $output/audit.json" >&2
	exit "$audit_exit"
fi
printf 'formal offline evidence complete (classification result is separate): %s\n' "$output"
