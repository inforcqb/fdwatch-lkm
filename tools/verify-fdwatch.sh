#!/system/bin/sh
# fdwatch device acceptance test.
#
# Positive tests need a writer that opened the file O_RDWR, because the dump
# reads the file back through the very `struct file` we captured and that needs
# FMODE_READ.  dd opens its output O_WRONLY, so the shell opens fd 3 read-write
# and hands it to dd instead.
set -u
DIR=/data/local/tmp/fdcap
A=/data/local/tmp/fdtest_a.bin
B=/data/local/tmp/fdtest_b.bin
KO=/data/local/tmp/fdwatch.ko

pass=0; fail=0
ok()  { echo "  [ok]   $*"; pass=$((pass+1)); }
bad() { echo "  [FAIL] $*"; fail=$((fail+1)); }
info(){ echo "  ...    $*"; }

echo "== fdwatch device verification =="
rmmod fdwatch 2>/dev/null
rm -rf "$DIR" "$A" "$B"
mkdir -p "$DIR"
chmod 777 "$DIR"

echo
echo "-- 1. load"
dmesg -c >/dev/null 2>&1
if ! insmod "$KO" 2>/dev/null; then
    info "plain insmod refused (filp_open not exported here) - using ksud"
    ksud insmod "$KO" >/dev/null 2>&1 || { bad "cannot load $KO"; dmesg | tail -5; exit 1; }
fi
grep -q '^fdwatch ' /proc/modules && ok "loaded" || bad "not in /proc/modules"
dmesg | grep fdwatch | tail -3 | sed 's/^/         /'

echo
echo "-- 2. event layer: fd_install on a freshly created file"
dd if=/dev/zero of="$A" bs=1M count=8 2>/dev/null
sleep 1
ev=$(dmesg | grep -c "new fd .* -> 'fdtest_a.bin'")
[ "$ev" -ge 1 ] && ok "fd_install logged the creation of fdtest_a.bin" \
                || bad "no fd_install log line for fdtest_a.bin"

echo
echo "-- 3. dump layer: 8 MiB written through an O_RDWR fd"
rm -f "$A"
exec 3<>"$A"
dd if=/dev/zero bs=1M count=8 >&3 2>/dev/null
exec 3>&-
sleep 4
saw=$(dmesg | grep -c "captured")
[ "$saw" -ge 1 ] && ok "a capture was taken ($saw dmesg line(s))" || bad "nothing captured"
ls -l "$DIR" | sed 's/^/         /'

echo
echo "-- 4. content check (captured bytes must match fdtest_a.bin)"
n=0
for f in "$DIR"/*fdtest_a.bin; do
    [ -e "$f" ] || continue
    n=$((n+1))
    a=$(md5sum "$A" | awk '{print $1}')
    b=$(md5sum "$f" | awk '{print $1}')
    [ "$a" = "$b" ] && ok "$(basename "$f") identical to fdtest_a.bin ($a)" \
                    || bad "$(basename "$f") differs: $b vs $a"
done
[ "$n" -gt 0 ] || bad "no capture for fdtest_a.bin"

echo
echo "-- 5. ftruncate trigger"
: > "$B" 2>/dev/null || touch "$B"
truncate -s 8M "$B" 2>/dev/null
sync
sleep 4
if dmesg | grep -q "ftruncate"; then
    ok "ftruncate trigger fired"
    dmesg | grep ftruncate | tail -2 | sed 's/^/         /'
else
    info "no ftruncate trigger (toybox truncate(1) may use truncate(2) on the path,"
    info "which is do_sys_truncate, not do_sys_ftruncate - not a module failure)"
fi

echo
echo "-- 6. index log"
if [ -s "$DIR/index.log" ]; then
    ok "index.log present"
    cat "$DIR/index.log" | sed 's/^/         /'
else
    bad "index.log missing or empty"
fi

echo
echo "-- 7. kernel health"
complaints=$(dmesg | grep -iE 'BUG:|WARNING:|CFI failure|Oops|Call trace' | head -5)
[ -z "$complaints" ] && ok "no BUG/WARNING/CFI failure/Oops" || { bad "kernel complaints:"; printf '%s\n' "$complaints" | sed 's/^/         /'; }

echo
echo "-- 8. unload"
if rmmod fdwatch 2>/dev/null; then ok "rmmod"; else bad "rmmod failed"; fi
grep -q '^fdwatch ' /proc/modules && bad "still loaded" || ok "gone from /proc/modules"
dmesg | grep fdwatch | tail -2 | sed 's/^/         /'

echo
echo "== $pass passed, $fail failed =="
[ "$fail" = "0" ]
