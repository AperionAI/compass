# demo.tape — reproducible "Compass scores a governance posture" GIF
#
# Regenerate:
#   brew install vhs                       # https://github.com/charmbracelet/vhs
#   cargo build --release
#   cargo run --example gen_fixtures       # writes ./demo/*
#   vhs scripts/demo.tape                  # writes docs/img/compass-demo.gif
#
# Deterministic: it drives the same binary + committed fixtures every run,
# so the GIF never drifts from what Compass actually scores.

Output docs/img/compass-demo.gif

Set Shell bash
Set FontSize 20
Set Width 1280
Set Height 760
Set Padding 28
Set TypingSpeed 38ms

# Brand-matched dark theme (Aperion navy + cyan).
Set Theme { "name": "compass", "background": "#0b1220", "foreground": "#e6edf6", "cursor": "#38bdf8", "black": "#0b1220", "red": "#f87171", "green": "#34d399", "yellow": "#fbbf24", "blue": "#38bdf8", "magenta": "#a78bfa", "cyan": "#22d3ee", "white": "#e6edf6", "brightBlack": "#24344d", "brightRed": "#f87171", "brightGreen": "#6ee7b7", "brightYellow": "#fbbf24", "brightBlue": "#60a5fa", "brightMagenta": "#a78bfa", "brightCyan": "#2dd4bf", "brightWhite": "#f8fafc" }

Hide
Type "export PATH=$PWD/target/release:$PATH" Enter
Type "clear" Enter
Show

# Beat 1 — the frameworks Compass ships with
Type "# two governance frameworks, bundled, offline:"
Enter
Sleep 700ms
Type "compass frameworks"
Enter
Sleep 2600ms

# Beat 2 — independently verify a tamper-evident audit chain
Type "# verify an exported audit chain with only the key -->"
Enter
Sleep 700ms
Type "compass verify --chain demo/chain.jsonl --chain-hmac-key file:demo/chain.key"
Enter
Sleep 2600ms

# Beat 3 — score the posture from answers + evidence
Type "# score answers + logs into one report (CI exit code and all):"
Enter
Sleep 700ms
Type "compass report --assessment demo/compass-assessment.yaml --out compass-report.html"
Enter
Sleep 3600ms

# Hold the final frame so the scorecard is readable in the loop
Sleep 2200ms
