#!/usr/bin/env bash
# wcurl — Regression Test Suite
#
# Run: bash tests/wcurl-test.sh
# Requires: Warden running on localhost:7400 with OpenAI key configured

set -uo pipefail

WCURL="$(dirname "$0")/../bin/wcurl"
WARDEN_HOST="${WARDEN_HOST:-http://localhost:7400}"
PASSED=0
FAILED=0
FAILURES=()

assert() {
    local name="$1"
    local condition="$2"
    if eval "$condition"; then
        PASSED=$((PASSED + 1))
        echo "  ✅ $name"
    else
        FAILED=$((FAILED + 1))
        FAILURES+=("$name")
        echo "  ❌ $name"
    fi
}

assert_eq() {
    local name="$1"
    local expected="$2"
    local actual="$3"
    if [ "$expected" = "$actual" ]; then
        PASSED=$((PASSED + 1))
        echo "  ✅ $name"
    else
        FAILED=$((FAILED + 1))
        FAILURES+=("$name (expected: $expected, got: $actual)")
        echo "  ❌ $name (expected: $expected, got: $actual)"
    fi
}

assert_contains() {
    local name="$1"
    local haystack="$2"
    local needle="$3"
    if echo "$haystack" | grep -q "$needle"; then
        PASSED=$((PASSED + 1))
        echo "  ✅ $name"
    else
        FAILED=$((FAILED + 1))
        FAILURES+=("$name (missing: $needle)")
        echo "  ❌ $name (missing: $needle)"
    fi
}

assert_not_contains() {
    local name="$1"
    local haystack="$2"
    local needle="$3"
    if ! echo "$haystack" | grep -q "$needle"; then
        PASSED=$((PASSED + 1))
        echo "  ✅ $name"
    else
        FAILED=$((FAILED + 1))
        FAILURES+=("$name (should not contain: $needle)")
        echo "  ❌ $name (should not contain: $needle)"
    fi
}

echo "🔒 wcurl — Regression Test Suite"
echo "=================================================="

# Pre-flight
echo ""
echo "🔧 Pre-flight"
assert "wcurl script exists" "[ -f '$WCURL' ]"
assert "wcurl is executable" "[ -x '$WCURL' ]"
HEALTH=$(curl -s "$WARDEN_HOST/health" 2>/dev/null)
assert "Warden is running" 'echo "$HEALTH" | grep -q "ok"'

# ── Help / Usage ──
echo ""
echo "📖 Help & Usage"
HELP=$("$WCURL" 2>&1 || true)
assert_contains "Shows usage when no args" "$HELP" "Usage"
assert_contains "Shows WARDEN_HOST env var" "$HELP" "WARDEN_HOST"
assert_contains "Mentions proxy routing" "$HELP" "proxy"

# ── URL Rewriting ──
echo ""
echo "🔄 URL Rewriting"

# Test with --dry-run style: use -v and capture what curl does
# We'll check by doing an actual call and verifying it works

# Registered service (OpenAI) — should route through proxy
RESULT=$(WARDEN_HOST="$WARDEN_HOST" "$WCURL" -s -H "Origin: http://localhost:7400" \
    https://api.openai.com/v1/models 2>&1)
assert_contains "Routes OpenAI through proxy" "$RESULT" "data"
assert_not_contains "OpenAI result has no auth error" "$RESULT" "invalid_api_key"

# Non-registered URL — should pass through directly (will fail since it's not a real URL)
RESULT=$(WARDEN_HOST="$WARDEN_HOST" "$WCURL" -s \
    https://httpbin.org/get 2>&1 || true)
# If it went direct, we'd get httpbin response or connection error — NOT a proxy error
assert_not_contains "Non-registered URL bypasses proxy" "$RESULT" "Origin not allowed"

# ── curl Flag Passthrough ──
echo ""
echo "🏷️  curl Flag Passthrough"

# -s flag (silent)
RESULT=$(WARDEN_HOST="$WARDEN_HOST" "$WCURL" -s -H "Origin: http://localhost:7400" \
    https://api.openai.com/v1/models 2>&1)
assert_not_contains "-s flag suppresses progress" "$RESULT" "% Total"

# -H flag (custom headers)
RESULT=$(WARDEN_HOST="$WARDEN_HOST" "$WCURL" -s \
    -H "Origin: http://localhost:7400" \
    -H "X-Custom-Header: test123" \
    https://api.openai.com/v1/models 2>&1)
assert_contains "Custom headers pass through" "$RESULT" "data"

# -X and -d flags (POST with data)
RESULT=$(WARDEN_HOST="$WARDEN_HOST" "$WCURL" -s \
    -H "Origin: http://localhost:7400" \
    -H "Content-Type: application/json" \
    -X POST \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say OK"}],"max_tokens":5}' \
    https://api.openai.com/v1/chat/completions 2>&1)
assert_contains "POST with -X -d works" "$RESULT" "choices"

# --data flag (alternate)
RESULT=$(WARDEN_HOST="$WARDEN_HOST" "$WCURL" -s \
    -H "Origin: http://localhost:7400" \
    -H "Content-Type: application/json" \
    --data '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say OK"}],"max_tokens":5}' \
    https://api.openai.com/v1/chat/completions 2>&1)
assert_contains "--data flag works" "$RESULT" "choices"

# ── Proxy Authentication ──
echo ""
echo "🔑 Proxy Authentication"

# Request succeeds without any API key (proxy injects it)
RESULT=$(WARDEN_HOST="$WARDEN_HOST" "$WCURL" -s \
    -H "Origin: http://localhost:7400" \
    https://api.openai.com/v1/models 2>&1)
assert_not_contains "Works without API key" "$RESULT" "invalid_api_key"
assert_not_contains "Works without API key (no 401)" "$RESULT" "401"

# Request succeeds WITH a fake API key (proxy strips and replaces)
RESULT=$(WARDEN_HOST="$WARDEN_HOST" "$WCURL" -s \
    -H "Origin: http://localhost:7400" \
    -H "Authorization: Bearer sk-FAKE-grandmas-phone-number" \
    https://api.openai.com/v1/models 2>&1)
assert_contains "Fake API key gets replaced by proxy" "$RESULT" "data"
assert_not_contains "Fake key doesnt cause auth error" "$RESULT" "invalid_api_key"

# ── WARDEN_HOST Override ──
echo ""
echo "🌐 WARDEN_HOST Override"

# Wrong host should fail
RESULT=$(WARDEN_HOST="http://localhost:9999" "$WCURL" -s \
    https://api.openai.com/v1/models 2>&1 || true)
assert_not_contains "Wrong WARDEN_HOST fails gracefully" "$RESULT" "data"

# ── Edge Cases ──
echo ""
echo "⚠️  Edge Cases"

# URL with query parameters
RESULT=$(WARDEN_HOST="$WARDEN_HOST" "$WCURL" -s \
    -H "Origin: http://localhost:7400" \
    "https://api.openai.com/v1/models?foo=bar" 2>&1)
assert_contains "URL with query params works" "$RESULT" "data"

# URL with path
RESULT=$(WARDEN_HOST="$WARDEN_HOST" "$WCURL" -s \
    -H "Origin: http://localhost:7400" \
    -H "Content-Type: application/json" \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say EDGE"}],"max_tokens":5}' \
    https://api.openai.com/v1/chat/completions 2>&1)
assert_contains "Deep path works (/v1/chat/completions)" "$RESULT" "choices"

# Multiple -H flags
RESULT=$(WARDEN_HOST="$WARDEN_HOST" "$WCURL" -s \
    -H "Origin: http://localhost:7400" \
    -H "X-One: 1" \
    -H "X-Two: 2" \
    -H "X-Three: 3" \
    https://api.openai.com/v1/models 2>&1)
assert_contains "Multiple -H flags preserved" "$RESULT" "data"

# ── Bootstrap Endpoint ──
echo ""
echo "📦 Bootstrap"

# /tools/wcurl serves the script
BOOTSTRAP=$(curl -s "$WARDEN_HOST/tools/wcurl" 2>&1)
assert_contains "Bootstrap endpoint serves script" "$BOOTSTRAP" "#!/usr/bin/env bash"
assert_contains "Bootstrap script has wcurl logic" "$BOOTSTRAP" "WARDEN_HOST"

# Downloaded script matches local script
LOCAL_HASH=$(sha256sum "$WCURL" | cut -d' ' -f1)
REMOTE_HASH=$(curl -s "$WARDEN_HOST/tools/wcurl" | sha256sum | cut -d' ' -f1)
assert_eq "Bootstrap matches local wcurl" "$LOCAL_HASH" "$REMOTE_HASH"

# ── Summary ──
echo ""
echo "=================================================="
echo "📋 Results: $PASSED passed, $FAILED failed"
if [ ${#FAILURES[@]} -gt 0 ]; then
    echo ""
    echo "❌ Failures:"
    for f in "${FAILURES[@]}"; do
        echo "   - $f"
    done
fi
echo ""
exit $FAILED
