#!/usr/bin/env sh
# shade installer — Linux / macOS
# curl -fsSL https://raw.githubusercontent.com/TheNeoNovo/Shadechat/main/install.sh | sh

set -e
REPO="https://raw.githubusercontent.com/TheNeoNovo/Shadechat/main"
GRN='\033[0;32m'; YEL='\033[0;33m'; MAG='\033[0;35m'; RED='\033[0;31m'; RST='\033[0m'
ok()   { printf "${GRN}[ok]${RST} %s\n" "$1"; }
warn() { printf "${YEL}[!] ${RST} %s\n" "$1"; }
fail() { printf "${RED}[x] ${RST} %s\n" "$1"; exit 1; }

echo ""
printf "${MAG}shade installer${RST} — encrypted LAN chat\n\n"

find_python() {
    for cmd in python3 python python3.12 python3.11 python3.10 python3.9; do
        if command -v "$cmd" >/dev/null 2>&1; then
            r=$("$cmd" -c "import sys;print(int(sys.version_info>=(3,7)))" 2>/dev/null)
            [ "$r" = "1" ] && echo "$cmd" && return 0
        fi
    done
    return 1
}

PYTHON=$(find_python || true)

if [ -z "$PYTHON" ]; then
    warn "Python 3.7+ not found."
    printf "  Install now? [Y/n] "; read -r ans; ans=${ans:-Y}
    case "$ans" in
        [Yy]*)
            case "$(uname -s)" in
                Darwin*)
                    command -v brew >/dev/null 2>&1 && brew install python3 || {
                        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
                        brew install python3
                    } ;;
                Linux*)
                    command -v apt-get >/dev/null 2>&1 && sudo apt-get install -y python3 ||
                    command -v dnf     >/dev/null 2>&1 && sudo dnf install -y python3 ||
                    command -v pacman  >/dev/null 2>&1 && sudo pacman -S --noconfirm python ||
                    fail "Install Python 3.7+ from https://python.org" ;;
            esac
            PYTHON=$(find_python || true)
            [ -z "$PYTHON" ] && fail "Python not found. Open a new terminal and retry." ;;
        *) fail "Python 3.7+ required." ;;
    esac
fi

ok "Python: $($PYTHON --version 2>&1)"

IDIR="$HOME/.shade-app"
BINDIR="$HOME/.neo/bin"
mkdir -p "$IDIR" "$BINDIR"

if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$REPO/shade.py" -o "$IDIR/shade.py"
else
    wget -q "$REPO/shade.py" -O "$IDIR/shade.py"
fi
chmod +x "$IDIR/shade.py"
ok "Downloaded shade.py"

printf '#!/usr/bin/env sh\nexec "%s" "%s/shade.py" "$@"\n' "$PYTHON" "$IDIR" > "$BINDIR/shade"
chmod +x "$BINDIR/shade"
ok "Created shade command"

case ":$PATH:" in
    *":$BINDIR:"*) ;;
    *)
        PROF=""
        [ -n "$ZSH_VERSION" ] && PROF="$HOME/.zshrc"
        [ -z "$PROF" ] && [ -f "$HOME/.bash_profile" ] && PROF="$HOME/.bash_profile"
        [ -z "$PROF" ] && PROF="$HOME/.bashrc"
        printf '\nexport PATH="%s:$PATH"\n' "$BINDIR" >> "$PROF"
        warn "Run: source $PROF  (or open a new terminal)"
        ;;
esac

echo ""
ok "shade installed. Type:"
echo ""
printf "    ${MAG}shade <room>${RST}         join an encrypted room\n"
printf "    ${MAG}shade keys${RST}           your key fingerprint\n"
printf "    ${MAG}shade help${RST}           all commands\n"
echo ""
