#!/bin/bash
#
# Strix One-Click Launcher
# Starts both the backend server and desktop UI
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${BLUE}"
    echo "  ╔═══════════════════════════════════════════════════════════╗"
    echo "  ║                                                           ║"
    echo "  ║   🦉 Strix - Autonomous AI Security Agent                ║"
    echo "  ║                                                           ║"
    echo "  ╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    # Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required but not installed."
        exit 1
    fi
    
    # Node.js
    if ! command -v node &> /dev/null; then
        log_error "Node.js is required but not installed."
        exit 1
    fi
    
    # pnpm
    if ! command -v pnpm &> /dev/null; then
        log_warn "pnpm not found, installing..."
        npm install -g pnpm
    fi
    
    log_info "All core dependencies satisfied."
}

check_optional_tools() {
    log_info "Checking optional security tools..."
    
    local tools=("nuclei" "httpx" "ffuf" "katana" "sqlmap")
    local missing=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_warn "Missing optional tools: ${missing[*]}"
        log_warn "Install them for full functionality:"
        echo ""
        echo "  # Go tools (requires Go installed)"
        echo "  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        echo "  go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
        echo "  go install github.com/ffuf/ffuf/v2@latest"
        echo "  go install github.com/projectdiscovery/katana/cmd/katana@latest"
        echo ""
        echo "  # Python tool"
        echo "  pipx install sqlmap"
        echo ""
    else
        log_info "All security tools installed."
    fi
}

setup_python_env() {
    log_info "Setting up Python environment..."
    
    if [ ! -d ".venv" ]; then
        log_info "Creating virtual environment..."
        python3 -m venv .venv
    fi
    
    source .venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip -q
    
    # Install core dependencies
    log_info "Installing Python dependencies..."
    pip install -q \
        fastapi \
        uvicorn \
        httpx \
        litellm \
        openai \
        pydantic \
        rich \
        textual \
        docker \
        pyyaml \
        requests \
        tenacity \
        playwright \
        xmltodict \
        jinja2 \
        aiofiles \
        websockets \
        2>/dev/null || true
    
    # Install package in development mode if possible
    pip install -q -e . 2>/dev/null || true
    
    # Install GUI dependencies (optional)
    log_info "Installing GUI dependencies (optional)..."
    pip install -q PyQt6 markdown 2>/dev/null || log_warn "PyQt6 installation skipped (optional)"
    
    log_info "Python dependencies installed."
}

setup_frontend() {
    log_info "Setting up frontend..."
    
    cd desktop
    if [ ! -d "node_modules" ]; then
        pnpm install
    fi
    cd ..
}

start_backend() {
    log_info "Starting backend server on port 8000..."
    
    source .venv/bin/activate
    
    # Kill existing server if running
    pkill -f "uvicorn strix.server.app:app" 2>/dev/null || true
    
    # Start server in background
    cd "$SCRIPT_DIR"
    nohup python -m uvicorn strix.server.app:app --host 0.0.0.0 --port 8000 > logs/backend.log 2>&1 &
    echo $! > .backend.pid
    
    # Wait for server to start
    sleep 2
    
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        log_info "Backend server started successfully."
    else
        log_warn "Backend may still be starting..."
    fi
}

start_frontend() {
    log_info "Starting frontend on port 5173..."
    
    cd desktop
    
    # Kill existing dev server if running
    pkill -f "vite" 2>/dev/null || true
    
    # Start frontend in background
    nohup pnpm dev > ../logs/frontend.log 2>&1 &
    echo $! > ../.frontend.pid
    
    cd ..
    
    sleep 3
    log_info "Frontend started successfully."
}

start_tauri() {
    log_info "Starting Tauri desktop app..."
    
    cd desktop
    pnpm tauri:dev
}

open_browser() {
    local url="http://localhost:5173"
    
    sleep 2
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        open "$url"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        xdg-open "$url" 2>/dev/null || true
    fi
    
    log_info "Opened browser at $url"
}

stop_all() {
    log_info "Stopping all services..."
    
    if [ -f .backend.pid ]; then
        kill $(cat .backend.pid) 2>/dev/null || true
        rm .backend.pid
    fi
    
    if [ -f .frontend.pid ]; then
        kill $(cat .frontend.pid) 2>/dev/null || true
        rm .frontend.pid
    fi
    
    pkill -f "uvicorn strix.server.app:app" 2>/dev/null || true
    pkill -f "vite" 2>/dev/null || true
    
    log_info "All services stopped."
}

show_help() {
    echo "Usage: ./start.sh [command]"
    echo ""
    echo "Commands:"
    echo "  dev       Start in development mode (backend + frontend)"
    echo "  desktop   Start Tauri desktop app"
    echo "  backend   Start only the backend server"
    echo "  frontend  Start only the frontend dev server"
    echo "  stop      Stop all services"
    echo "  status    Show service status"
    echo "  tools     Install security tools"
    echo "  help      Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  STRIX_LLM          LLM model to use (default: openai/gpt-4o)"
    echo "  OPENAI_API_KEY     OpenAI API key"
    echo "  ANTHROPIC_API_KEY  Anthropic API key"
}

show_status() {
    echo ""
    echo "Service Status:"
    echo "---------------"
    
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        echo -e "Backend:  ${GREEN}Running${NC} (http://localhost:8000)"
    else
        echo -e "Backend:  ${RED}Stopped${NC}"
    fi
    
    if curl -s http://localhost:5173 > /dev/null 2>&1; then
        echo -e "Frontend: ${GREEN}Running${NC} (http://localhost:5173)"
    else
        echo -e "Frontend: ${RED}Stopped${NC}"
    fi
    
    echo ""
}

install_tools() {
    log_info "Installing security tools..."
    
    if command -v go &> /dev/null; then
        log_info "Installing Go-based tools..."
        go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        go install github.com/projectdiscovery/httpx/cmd/httpx@latest
        go install github.com/ffuf/ffuf/v2@latest
        go install github.com/projectdiscovery/katana/cmd/katana@latest
    else
        log_warn "Go not installed, skipping Go tools."
    fi
    
    if command -v pipx &> /dev/null; then
        log_info "Installing Python tools..."
        pipx install sqlmap
    else
        log_warn "pipx not installed, skipping Python tools."
    fi
    
    log_info "Tool installation complete."
}

# Create logs directory
mkdir -p logs

# Main
print_banner

case "${1:-dev}" in
    dev)
        check_dependencies
        check_optional_tools
        setup_python_env
        setup_frontend
        start_backend
        start_frontend
        open_browser
        
        echo ""
        log_info "Strix is running!"
        echo ""
        echo "  🌐 Web UI:  http://localhost:5173"
        echo "  📡 API:     http://localhost:8000"
        echo "  📖 Docs:    http://localhost:8000/docs"
        echo ""
        echo "Press Ctrl+C to stop..."
        
        # Wait for interrupt
        trap stop_all EXIT
        wait
        ;;
    desktop)
        check_dependencies
        setup_python_env
        setup_frontend
        start_backend
        start_tauri
        ;;
    backend)
        setup_python_env
        start_backend
        ;;
    frontend)
        setup_frontend
        start_frontend
        open_browser
        ;;
    stop)
        stop_all
        ;;
    status)
        show_status
        ;;
    tools)
        install_tools
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        log_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
