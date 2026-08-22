#!/usr/bin/env bash
# Move the floating branch-tag used by the automated release workflow.
set -euo pipefail

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_REF_NAME:?GITHUB_REF_NAME is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${RELEASE_TAG:?RELEASE_TAG is required}"

readonly read_ref="repos/$GITHUB_REPOSITORY/git/ref/tags/$RELEASE_TAG"
readonly write_ref="repos/$GITHUB_REPOSITORY/git/refs/tags/$RELEASE_TAG"
readonly GH_BIN="${GH_BIN:-gh}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

write_summary() {
  [[ -n "${GITHUB_STEP_SUMMARY:-}" ]] || return 0
  printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY"
}

fail_api() {
  local phase="$1" status="$2" stdout_file="$3" stderr_file="$4"
  local details
  details="branch=$GITHUB_REF_NAME tag=$RELEASE_TAG sha=$GITHUB_SHA run=https://github.com/$GITHUB_REPOSITORY/actions/runs/${GITHUB_RUN_ID:-unknown}"
  echo "::error title=Branch tag update failed::$phase (exit $status): $details"
  echo "Branch tag update failed: $phase (exit $status)"
  echo "$details"
  [[ ! -s "$stdout_file" ]] || { echo 'API response:'; cat "$stdout_file"; }
  [[ ! -s "$stderr_file" ]] || { echo 'API error:'; cat "$stderr_file"; }
  write_summary "## Branch tag update failed"
  write_summary "- Phase: \`$phase\`"
  write_summary "- $details"
  write_summary "- Exit status: \`$status\`"
  exit "$status"
}

is_not_found() {
  grep -Eq 'HTTP 404|"status"[[:space:]]*:[[:space:]]*404' "$1" "$2"
}

run_write() {
  local phase="$1"
  shift
  local stdout_file="$tmp_dir/${phase// /_}.stdout"
  local stderr_file="$tmp_dir/${phase// /_}.stderr"
  if "$@" >"$stdout_file" 2>"$stderr_file"; then
    cat "$stdout_file"
    return 0
  fi
  local status=$?
  fail_api "$phase" "$status" "$stdout_file" "$stderr_file"
}

read_stdout="$tmp_dir/read.stdout"
read_stderr="$tmp_dir/read.stderr"
if "$GH_BIN" api "$read_ref" >"$read_stdout" 2>"$read_stderr"; then
  action=updated
  run_write 'update existing tag ref' "$GH_BIN" api --method PATCH "$write_ref" -f "sha=$GITHUB_SHA" -F force=true
else
  status=$?
  if is_not_found "$read_stdout" "$read_stderr"; then
    action=created
    run_write 'create missing tag ref' "$GH_BIN" api --method POST "repos/$GITHUB_REPOSITORY/git/refs" \
      -f "ref=refs/tags/$RELEASE_TAG" -f "sha=$GITHUB_SHA"
  else
    fail_api 'read tag ref' "$status" "$read_stdout" "$read_stderr"
  fi
fi

verify_stdout="$tmp_dir/verify.stdout"
verify_stderr="$tmp_dir/verify.stderr"
if "$GH_BIN" api "$read_ref" >"$verify_stdout" 2>"$verify_stderr"; then
  :
else
  status=$?
  fail_api 'verify tag ref' "$status" "$verify_stdout" "$verify_stderr"
fi

read -r ref_type ref_sha < <(python3 - "$verify_stdout" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
obj = document.get("object", {})
print(obj.get("type", ""), obj.get("sha", ""))
PY
)
if [[ "$ref_type" != commit || "$ref_sha" != "$GITHUB_SHA" ]]; then
  echo "::error title=Branch tag verification failed::Expected commit $GITHUB_SHA, got $ref_type $ref_sha"
  write_summary "## Branch tag verification failed"
  write_summary "- branch=$GITHUB_REF_NAME tag=$RELEASE_TAG expected=$GITHUB_SHA actual_type=$ref_type actual_sha=$ref_sha"
  exit 1
fi

message="Branch tag $action: branch=$GITHUB_REF_NAME tag=$RELEASE_TAG sha=$ref_sha type=$ref_type run=https://github.com/$GITHUB_REPOSITORY/actions/runs/${GITHUB_RUN_ID:-unknown}"
echo "$message"
write_summary "## Branch tag updated"
write_summary "- $message"
