#!/bin/bash

# Volatility3 Quick Format & Lint Script
# Detects changed files, fixes formatting with black, and runs ruff
# Usage: ./ci_local.sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Get files to check
if [ $# -eq 0 ]; then
    # No arguments - check staged files or recent changes
    if git rev-parse --git-dir > /dev/null 2>&1; then
        FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.py$' || true)
        if [ -z "$FILES" ]; then
            FILES=$(git diff --name-only HEAD~1 | grep '\.py$' || true)
        fi
        if [ -z "$FILES" ]; then
            # Check unstaged changes too
            FILES=$(git diff --name-only | grep '\.py$' || true)
        fi
    else
        FILES=$(find volatility3 -name "*.py" -mtime -1 2>/dev/null || true)
    fi
else
    # Use provided files
    FILES="$*"
fi

if [ -z "$FILES" ]; then
    log_info "No Python files to process"
    exit 0
fi

log_info "Processing files: $(echo $FILES | tr '\n' ' ')"

# Black formatting - FIX the formatting automatically
if command -v black >/dev/null 2>&1; then
    log_info "Running black formatter (fixing issues)..."
    for file in $FILES; do
        if [ -f "$file" ]; then
            black "$file" && log_info "✓ Formatted $file"
        fi
    done
    log_success "Black formatting completed"
else
    log_warning "Black not available - install with: pip install black"
fi

# Ruff linting
exit_code=0
if command -v ruff >/dev/null 2>&1; then
    log_info "Running ruff checks..."
    for file in $FILES; do
        if [ -f "$file" ]; then
            if ! ruff check "$file"; then
                log_error "Ruff found issues in $file"
                exit_code=1
            fi
        fi
    done
    if [ $exit_code -eq 0 ]; then
        log_success "Ruff checks passed"
    fi
else
    log_warning "Ruff not available - install with: pip install ruff"
fi

if [ $exit_code -eq 0 ]; then
    log_success "All checks passed! ✅"
else
    log_error "Some linting issues found! ❌"
fi

exit $exit_code
