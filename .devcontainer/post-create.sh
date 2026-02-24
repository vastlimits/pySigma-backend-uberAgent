#!/bin/bash
set -e

# -----------------------------------------------------------------------------
# Post-create script for dev container setup
# -----------------------------------------------------------------------------

WORKSPACE_DIR="/workspaces/pySigma-backend-uberAgent"
SIGMA_REPO_DIR="$HOME/sigma"
SIGMA_CLI_VENV="$HOME/sigma-cli"

echo "==> Installing Poetry..."
pipx install poetry

echo "==> Installing project dependencies..."
poetry install

echo "==> Creating output directories..."
mkdir -p rules out

echo "==> Cloning/updating SigmaHQ rules repository..."
if [ -d "$SIGMA_REPO_DIR" ]; then
    cd "$SIGMA_REPO_DIR" && git pull
else
    git clone --depth 1 https://github.com/SigmaHQ/sigma.git "$SIGMA_REPO_DIR"
fi

echo "==> Setting up sigma-cli virtual environment in $SIGMA_CLI_VENV..."
python -m venv "$SIGMA_CLI_VENV"
"$SIGMA_CLI_VENV/bin/pip" install --upgrade pip
# sigma-cli 1.0.6 requires pysigma >=0.11.19,<0.12.0, compatible with project's ^0.11.2
"$SIGMA_CLI_VENV/bin/pip" install sigma-cli==1.0.6
"$SIGMA_CLI_VENV/bin/pip" install -e "$WORKSPACE_DIR"

echo "==> Adding sigma alias to ~/.bashrc..."
cat >> ~/.bashrc << 'EOF'

# sigma-cli: use the dedicated venv automatically
sigma() {
    "$HOME/sigma-cli/bin/sigma" "$@"
}
export -f sigma
EOF

echo "==> Post-create setup complete!"
echo "    Run 'source ~/.bashrc' or open a new terminal to use 'sigma' command."
