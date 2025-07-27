#!/bin/bash
# filter-wrapper.sh - Smudge-only version

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

# Since this is smudge-only, we only decrypt
PIN=$(get_pin)
if [ -z "$PIN" ]; then
    # If no PIN, pass through unchanged (encrypted)
    cat
    exit 0
fi

# Decrypt the content
./fido2-derive --mode=dec --pin="$PIN"

