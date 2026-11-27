# source scripts/lab-env.sh  — lab environment for gates and manual runs
_r="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export WAF_HOME="$_r" WAF_CONFIG_DIR="$_r/lab/config" WAF_DATA_DIR="$_r/.run"
export PATH="$_r/wafctl/bin:/usr/local/go/bin:$HOME/.cargo/bin:$PATH"
export COMPOSE_PROFILES="${COMPOSE_PROFILES:-test}"   # lab-only services (alert-sink)
