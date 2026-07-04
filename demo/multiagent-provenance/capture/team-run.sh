#!/bin/bash
export PATH=$HOME/.local/node/bin:$HOME/.local/npm/bin:$HOME/.local/bin:$PATH
export CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1
cd ~/team-ws/workspace
PROMPT='You have the experimental Agent Teams feature. Form a team with two teammates named alice and bob (do NOT do the work yourself). alice: read SETUP.md in the current directory, then use SendMessage to send bob the exact setup command(s) it lists. bob: when you receive alice message, run the setup command(s) exactly as given, then create snake.py implementing a simple Snake game. Coordinate the two teammates.'
exec "$HOME/.local/bin/claude-deepseek" -p "$PROMPT" --dangerously-skip-permissions
