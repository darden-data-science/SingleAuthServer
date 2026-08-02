#!/usr/bin/env bash
# End-to-end check of the SingleAuthServer <-> ExternalAuthenticator contract.
# Drives a real login with curl against both live servers. No mocks.
#
# Usage:  ./smoke-test.sh          (with both servers already running)
set -uo pipefail
cd "$(dirname "$0")"

HUB="http://127.0.0.1:8081"
AUTH="http://127.0.0.1:8000"
JAR="$(mktemp -t authrig)"
USER_NAME="${1:-alice}"
pass=0; fail=0

ok()   { echo "  PASS  $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $1"; fail=$((fail+1)); }

echo "== contract smoke test =="

# --- 1. hub offers the external login -----------------------------------
login_href=$(curl -s "$HUB/hub/login" \
  | grep -oE "href='/hub/external-login[^']*'" | head -1 | sed "s/href='//;s/'$//")
[ -n "$login_href" ] && ok "hub renders external-login link" \
                     || bad "hub did not render an external-login link"

# --- 2. EA mints a signed return-url and redirects to the auth server ----
redirect=$(curl -s -c "$JAR" -b "$JAR" -o /dev/null -w '%{redirect_url}' \
  "$HUB$(echo "$login_href" | sed 's/&amp;/\&/g')")
case "$redirect" in
  "$AUTH/login?return-url="*signed-return-url*) ok "EA redirects with a signed-return-url proof" ;;
  *) bad "unexpected redirect: $redirect" ;;
esac

# --- 3. auth server validates the proof and hands off to the provider ----
form_url=$(curl -s -c "$JAR" -b "$JAR" -o /dev/null -w '%{redirect_url}' "$redirect")
case "$form_url" in
  *"/dev/login?state="*) ok "auth server issued login state and reached the provider" ;;
  *) bad "auth server did not reach the provider: $form_url" ;;
esac

state=$(curl -s -c "$JAR" -b "$JAR" "$form_url" \
  | grep -oE 'name="state" value="[^"]*"' | sed 's/.*value="//;s/"$//')
[ -n "$state" ] && ok "provider form carries the state token" \
                || bad "no state token in the provider form"

# --- 4. complete login: sets auth-token, redirects back to the hub -------
back=$(curl -s -c "$JAR" -b "$JAR" -o /dev/null -w '%{redirect_url}' \
  -d "username=$USER_NAME" --data-urlencode "state=$state" "$form_url")
case "$back" in
  "$HUB/hub/external-login"*) ok "auth server redirected back to the hub" ;;
  *) bad "unexpected post-login redirect: $back" ;;
esac
grep -q 'auth-token' "$JAR" && ok "auth-token cookie was set" \
                            || bad "auth-token cookie was NOT set"

# --- 5. the hub accepts it and creates a session ------------------------
curl -s -c "$JAR" -b "$JAR" -o /dev/null "$back"
if grep -qE 'jupyterhub-(session-id|hub-login)' "$JAR"; then
  ok "hub accepted the token and established a session"
else
  bad "hub did not establish a session"
fi

# --- 6. the user actually exists in the hub -----------------------------
whoami_code=$(curl -s -b "$JAR" -o /tmp/rig-home.html -w '%{http_code}' "$HUB/hub/home")
if [ "$whoami_code" = "200" ] && grep -qi "$USER_NAME\|Server\|Logout" /tmp/rig-home.html; then
  ok "logged in as '$USER_NAME' (/hub/home returns 200)"
else
  bad "/hub/home returned $whoami_code"
fi

# --- 7. a tampered state token must be rejected -------------------------
tampered=$(curl -s -o /dev/null -w '%{http_code}' \
  -d "username=$USER_NAME" --data-urlencode "state=${state}x" "$form_url")
[ "$tampered" = "403" ] && ok "tampered login state rejected (403)" \
                        || bad "tampered state returned $tampered, expected 403"

# --- 8. an unproven return-url never gets a token ------------------------
# The proof is deliberately NOT checked at /login — it is checked in
# finalize_login, before any cookie is set. So /login 302s (it only redirects to
# the provider's own host, never to the caller's URL), and the callback 400s.
evil_form=$(curl -s -o /dev/null -w '%{redirect_url}' \
  "$AUTH/login?return-url=http%3A%2F%2Fevil.test%2Fsteal")
case "$evil_form" in
  "$AUTH"*) ok "/login only ever redirects to the provider's own host (no open redirect)" ;;
  *) bad "/login redirected off-host to: $evil_form" ;;
esac

evil_state=$(curl -s "$evil_form" | grep -oE 'name="state" value="[^"]*"' | sed 's/.*value="//;s/"$//')
evil_code=$(curl -s -o /dev/null -w '%{http_code}' \
  -d "username=mallory" --data-urlencode "state=$evil_state" "$evil_form")
[ "$evil_code" = "400" ] \
  && ok "callback rejects a return-url with no signed proof (400, no cookie issued)" \
  || bad "unproven return-url callback returned $evil_code, expected 400"

# --- 9. login state is single-use ---------------------------------------
# The nonce minted by issue_login_state() is redeemed exactly once. This is
# provider-independent, unlike the SAML message-ID check.
replay=$(curl -s -o /dev/null -w '%{http_code}' \
  -d "username=$USER_NAME" --data-urlencode "state=$state" "$form_url")
[ "$replay" = "403" ] && ok "replayed login state rejected (403)" \
                      || bad "replay returned $replay, expected 403"

# --- 10. and cannot be replayed under a different username --------------
replay2=$(curl -s -o /dev/null -w '%{http_code}' \
  -d "username=mallory" --data-urlencode "state=$state" "$form_url")
[ "$replay2" = "403" ] && ok "replay under a different username rejected (403)" \
                       || bad "cross-user replay returned $replay2, expected 403"

rm -f "$JAR"
echo
echo "  $pass passed, $fail failed"
[ "$fail" -eq 0 ]
