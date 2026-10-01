#!/system/bin/sh
DIR=/data/local/tmp/fdcap
T=/data/local/tmp/fdtest.bin
P=/sys/module/fdwatch/parameters

rmmod fdwatch 2>/dev/null
rm -rf "$DIR"; mkdir -p "$DIR"; chmod 777 "$DIR"
rm -f "$T"
dmesg -c >/dev/null 2>&1

echo "=== 1. load (event layer on, debug_fds for 3 s) ==="
ksud insmod /data/local/tmp/fdwatch.ko debug_fds=1 >/dev/null 2>&1
sleep 1
dmesg | grep fdwatch | head -2
sleep 3
echo 0 > "$P/debug_fds" 2>/dev/null
echo "--- raw fd_install sample (debug) ---"
dmesg | grep 'fd_install fd=' | head -10
echo "--- passed the filter ---"
n_new=$(dmesg | grep -c 'new fd ')
echo "  new fd lines: $n_new"
dmesg | grep 'new fd ' | head -6

echo
echo "=== 2. positive test: dd writes 8 MiB (write-only fd -> pagecache path) ==="
dd if=/dev/zero of="$T" bs=1M count=8 2>&1 | tail -1
sleep 6
ls -l "$T"
echo "--- captures ---"
ls -l "$DIR" | sed 's/^/  /'
echo "--- index ---"
cat "$DIR/index.log" 2>/dev/null | sed 's/^/  /'
echo "--- md5 ---"
src=$(md5sum "$T" | awk '{print $1}')
for f in "$DIR"/*.bin; do
    [ -e "$f" ] || continue
    d=$(md5sum "$f" | awk '{print $1}')
    if [ "$d" = "$src" ]; then echo "  [ok]   $(basename "$f") identical ($(stat -c %s "$f") bytes)"
    else echo "  [FAIL] $(basename "$f") differs: $d vs $src"; fi
done

echo
echo "=== 3. health ==="
dmesg | grep -iE 'WARNING:|BUG:|CFI failure|Oops|Call trace' | head -4 || true
echo "  (none above means clean)"

echo
echo "=== 4. unload + counters ==="
rmmod fdwatch
sleep 1
dmesg | grep -E 'unloaded' | sed 's/^/  /'
