#!/bin/bash
# filter-wrapper.sh — used for Git clean/smudge filters

MODE="$1"
PIN_FILE="/tmp/fido2_pin_cache"

get_pin() {
    if [ -f "$PIN_FILE" ]; then
        cat "$PIN_FILE"
        return
    fi

    pin=$(pinentry-gtk-2 --title "FIDO2 PIN" --description "Bitte gib deinen FIDO2-PIN ein." <<EOF | grep ^D | cut -c3-
GETPIN
EOF
)
    
    if [ -n "$pin" ]; then
        echo "$pin" > "$PIN_FILE"
    fi
    echo "$pin"
}

# Entry point
case "$MODE" in
  encrypt)
    PIN=$(get_pin)
    if [ -z "$PIN" ]; then
        echo "[clean filter] No PIN provided, passing content unchanged." >&2
        cat
        exit 0
    fi

    ./fido2-derive --mode=enc --pin="$PIN"
    exit $?  # Output goes directly to Git

    ;;

  decrypt)
    PIN=$(get_pin)
    if [ -z "$PIN" ]; then
        echo "[smudge filter] No PIN provided, passing content unchanged." >&2
        cat
        exit 0
    fi

    ./fido2-derive --mode=dec --pin="$PIN"
    exit $?

    ;;

  *)
    echo "[filter-wrapper] Unknown mode: $MODE — passing content unchanged" >&2
    cat
    exit 0
    ;;
esac

