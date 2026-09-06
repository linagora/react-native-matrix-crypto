#!/usr/bin/env bash
set -euo pipefail

# The root README and the published package's README must be identical.
#
# They are two files rather than one because npm shows the package copy on the
# registry page and GitHub shows the root copy, and npm does not follow a
# symlink out of the package directory when packing. So the only mechanism
# available is a copy, and a copy kept in sync by hand drifts.
#
# It already did. A contributing section describing how to run the
# interoperability proof was added to the root copy alone -- which is the
# section a consumer arriving from npm would most want, and the one they would
# not have seen.
# CHANGELOG.md is the second pair, for the same reason and by the same
# mechanism. It shipped nowhere until it was named in the package's `files`
# list, so a consumer reading the registry page could not see what changed
# between the version they hold and the version they are installing without
# leaving npm for GitHub.
SYNCED_PAIRS="README.md packages/react-native-matrix-crypto/README.md
CHANGELOG.md packages/react-native-matrix-crypto/CHANGELOG.md"

# Refuse to pass having scanned nothing. A renamed or moved file would
# otherwise make `diff` fail loudly on a missing path, or -- worse, if someone
# "fixed" that with a `-N` -- make two absent files compare equal. The sibling
# gates carry the same guard for the same reason.
PAIRS_CHECKED=0
while read -r ROOT_COPY PKG_COPY; do
  [ -z "$ROOT_COPY" ] && continue
  for f in "$ROOT_COPY" "$PKG_COPY"; do
    if [ ! -s "$f" ]; then
      echo "FAIL: refusing to pass having scanned nothing."
      echo "      $f is missing or empty, so this gate cannot compare anything."
      exit 1
    fi
  done

  if ! diff -u "$ROOT_COPY" "$PKG_COPY"; then
    echo
    echo "FAIL: $ROOT_COPY and its package copy have diverged."
    echo "      The package copy is what npm shows a consumer. Copy the root one over it:"
    echo "        cp $ROOT_COPY $PKG_COPY"
    exit 1
  fi
  PAIRS_CHECKED=$((PAIRS_CHECKED + 1))
done <<EOF
$SYNCED_PAIRS
EOF

# The list itself could be emptied, and an empty loop passes silently. This is
# the same "refuse to pass having compared nothing" rule the per-file guard
# above states, applied one level up, to the list rather than to a file.
if [ "$PAIRS_CHECKED" -ne 2 ]; then
  echo "FAIL: refusing to pass having compared $PAIRS_CHECKED pair(s)."
  echo "      SYNCED_PAIRS names the files npm shows a consumer; two pairs"
  echo "      are expected, the README and the CHANGELOG."
  exit 1
fi

ROOT_README="README.md"

# --- "Every one of these runs in CI." ---------------------------------------
#
# The README's build-gate table stands under that sentence. On 2026-08-28 it
# was false in both directions at once: the table listed six gates where
# package.json declared seven, and the missing one -- gate:readme, this script
# -- was invoked by no workflow either. It had been written that same day,
# added to package.json, and wired into nothing, while the review that found
# it was closing seven other instances of a check that exists and never runs.
#
# So the sentence is enforced rather than repeated. Every `gate:*` script in
# package.json must appear in the workflow, as a step that runs it, and in the
# README's table, as a row that names it. A gate added tomorrow fails this
# gate until both are true, which is cheaper than finding out in a review.
WORKFLOW=".github/workflows/ci.yml"

if [ ! -s "$WORKFLOW" ]; then
  echo "FAIL: $WORKFLOW is missing or empty, so this gate cannot check that"
  echo "      the README's \"Every one of these runs in CI\" is true."
  exit 1
fi

GATES=$(node -e '
  const pkg = JSON.parse(require("fs").readFileSync("package.json", "utf8"));
  Object.keys(pkg.scripts || {})
    .filter(s => s.startsWith("gate:"))
    .forEach(s => console.log(s));
')

# Refuse to pass having compared nothing: an unreadable package.json or a
# renamed script prefix would leave this empty and every loop below would
# trivially agree.
if [ -z "${GATES//[[:space:]]/}" ]; then
  echo "FAIL: refusing to pass having compared nothing."
  echo "      package.json declares no gate:* script, which means this check"
  echo "      broke rather than that every gate is wired up."
  exit 1
fi

UNWIRED=""
UNLISTED=""
for gate in $GATES; do
  if ! grep -qE "^[[:space:]]*-[[:space:]]*run:[[:space:]]*yarn[[:space:]]+$gate[[:space:]]*$" "$WORKFLOW"; then
    UNWIRED="${UNWIRED:+$UNWIRED
}$gate"
  fi
  # Whitespace-tolerant, and it has to be. This was `grep -qF "| \`$gate\` |"`,
  # which requires exactly one space on each side of the cell -- and Prettier
  # pads every cell in a Markdown table out to the width of its column. Commit
  # 0e93565 ran Prettier over the READMEs and turned this gate red for all
  # thirteen gates at once, reporting that the table names none of them while
  # the table sat there naming all of them. That padding is what is committed
  # on main, so a gate that reads a table has to read the table as it is
  # actually written; the whitespace between the pipes was never the thing
  # being asserted.
  if ! grep -qE "^\|[[:space:]]*\`$gate\`[[:space:]]*\|" "$ROOT_README"; then
    UNLISTED="${UNLISTED:+$UNLISTED
}$gate"
  fi
done

if [ -n "$UNWIRED" ]; then
  echo "FAIL: a gate exists in package.json and no CI job runs it:"
  echo "$UNWIRED"
  echo "      Add a '- run: yarn <gate>' step to $WORKFLOW."
  echo "      A gate nobody runs is documentation, not enforcement."
  exit 1
fi

if [ -n "$UNLISTED" ]; then
  echo "FAIL: a gate runs in CI and the README's build-gate table does not"
  echo "      name it:"
  echo "$UNLISTED"
  echo "      That table stands under \"Every one of these runs in CI\", so a"
  echo "      missing row makes the sentence describe fewer checks than exist."
  exit 1
fi

GATE_COUNT=$(printf '%s\n' "$GATES" | grep -c .)

# --- The count in the prose, not only the rows in the table -----------------
#
# This gate held the rows, the scripts and the workflow to each other and
# counted nothing, so the sentence in "Why adopt it" that says how many gates
# there are drifted to one fewer than the table under it listed. Nothing
# failed. A reader who counts the rows finds the number in the prose is wrong,
# which is a small thing that costs a reader their trust in the larger claims
# beside it.
#
# Spelled rather than numeric, because that is how the sentence is written,
# and matched against the whole spelled range this repository could plausibly
# reach rather than against the current number alone: a match on the current
# number would pass on a README that names no count at all, which is the
# refusal-to-pass-having-scanned-nothing rule every gate here follows.
NUMBER_WORDS=(zero one two three four five six seven eight nine ten eleven
              twelve thirteen fourteen fifteen sixteen seventeen eighteen
              nineteen twenty)
GATE_WORD="${NUMBER_WORDS[$GATE_COUNT]:-}"
if [ -z "$GATE_WORD" ]; then
  echo "FAIL: $GATE_COUNT gates is past the range this check spells out."
  echo "      Extend NUMBER_WORDS in $0 rather than dropping the check."
  exit 1
fi

COUNT_SENTENCE=$(grep -oE 'There are [a-z]+, they all run in CI' "$ROOT_README" || true)
if [ -z "$COUNT_SENTENCE" ]; then
  echo "FAIL: refusing to pass having compared nothing."
  echo "      $ROOT_README no longer carries a \"There are <n>, they all run"
  echo "      in CI\" sentence, so this check cannot tell whether the count it"
  echo "      states is right. Restore the sentence or remove this check and"
  echo "      say why."
  exit 1
fi

if [ "$COUNT_SENTENCE" != "There are $GATE_WORD, they all run in CI" ]; then
  echo "FAIL: the README says \"$COUNT_SENTENCE\" and package.json declares"
  echo "      $GATE_COUNT gate:* scripts, which is \"$GATE_WORD\"."
  echo "      The prose and the table disagree, and a reader counts the table."
  exit 1
fi

echo "PASS: READMEs identical ($(wc -l < "$ROOT_README" | tr -d ' ') lines);"
echo "      all $GATE_COUNT gates run in CI, appear in the README's table, and"
echo "      match the count the README states in words"
