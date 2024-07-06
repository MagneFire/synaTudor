#!/bin/bash -e

HASH_FILE="$1"
TMP_DIR="$2"
OUT_DIR="$3"
DLLS=${@:4}

mkdir -p "$TMP_DIR"

#Download the driver executable and check hash
#INSTALLER1="$TMP_DIR/installer1.exe"
INSTALLER2="$TMP_DIR/installer2.exe"
#wget https://ftp.hp.com/pub/softpaq/sp138001-138500/sp138227.exe -O "$INSTALLER1"
#wget https://download.lenovo.com/consumer/mobiles/h4yf01af.exe -O "$INSTALLER2"
wget https://download.lenovo.com/consumer/mobiles/im7f04af07wp.exe -O "$INSTALLER2"
# shasum "$INSTALLER" | cut -d" " -f1 | cmp - "$HASH_FILE"

#Extract the driver
WINDRV="$TMP_DIR/windrv"
mkdir -p "$WINDRV"
innoextract -d "$WINDRV" "$INSTALLER2"
#7z e "$INSTALLER1" -o"$WINDRV" dchu_fpr/*

#Copy outputs
mkdir -p "$OUT_DIR"
for dll in $DLLS
do
    cp $(find "$WINDRV" -name "$dll") "$OUT_DIR/$dll"
done