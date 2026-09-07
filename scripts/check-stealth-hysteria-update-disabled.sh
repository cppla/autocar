#!/bin/sh
set -eu

scripts='scripts/stealth-active.sh scripts/stealth-pilot.sh scripts/stealth-full-lab.sh'

folded=$(
	for script in $scripts; do
		awk '
			BEGIN { buffer = ""; start = 0 }
			{
				line = $0
				sub(/^[[:space:]]+/, "", line)
				if (buffer == "") start = FNR
				buffer = buffer line
				if (buffer ~ /\\[[:space:]]*$/) {
					sub(/\\[[:space:]]*$/, " ", buffer)
					next
				}
				printf "%s:%d:%s\n", FILENAME, start, buffer
				buffer = ""
			}
			END {
				if (buffer != "") printf "%s:%d:%s\n", FILENAME, start, buffer
			}
		' "$script"
	done
)

launches=$(printf '%s\n' "$folded" | grep -E -- '--entrypoint /hysteria.* (server|client)( |$).* -c( |$)' || true)
actual=$(printf '%s\n' "$launches" | sed '/^$/d' | wc -l | tr -d ' ')
if [ "$actual" -ne 7 ]; then
	echo "expected exactly 7 audited Hysteria client/server shell launches; found $actual" >&2
	printf '%s\n' "$launches" >&2
	exit 1
fi

printf '%s\n' "$launches" | while IFS= read -r launch; do
	flag_count=$(printf '%s\n' "$launch" | awk '{
		count = 0
		for (field = 1; field <= NF; field++) {
			if ($field == "--disable-update-check") count++
		}
		print count
	}')
	if [ "$flag_count" -ne 1 ]; then
		echo "Hysteria launch must contain --disable-update-check exactly once:" >&2
		printf '%s\n' "$launch" >&2
		exit 1
	fi
done

echo "Hysteria update-check launch gate passed"
