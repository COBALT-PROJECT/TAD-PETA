#!/bin/bash

# Configuration
DURATION_MINUTES=5
DEST_DIR="/home/abdul/DigitalTwin/TAD-PETA/TAD/data"
MOUNT_POINT="/mnt/pcaps"
SERVER="10.0.0.40:/srv/pcap-share"

# Ask user for the label
read -p "Enter the label for this harvest ('benign' or 'attack'): " LABEL

# Default to benign if empty
if [ -z "$LABEL" ]; then
    LABEL="benign"
fi

mkdir -p "$DEST_DIR"

echo "=========================================="
echo " Starting Harvester for $DURATION_MINUTES minutes"
echo " Label: $LABEL"
echo " Saving to: $DEST_DIR"
echo "=========================================="

for (( i=1; i<=DURATION_MINUTES; i++ ))
do
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    echo "[$(date +'%H:%M:%S')] Minute $i/$DURATION_MINUTES: Harvesting..."
    
    # 1. Mount the shared drive
    sudo mount -t nfs "$SERVER" "$MOUNT_POINT"
    
    # 2. Copy the files and rename them with the label and timestamp
    # Changed from vmbr2 to vmbr1
    if [ -f "$MOUNT_POINT/vmbr1_selected_latest.pcap" ]; then
        cp "$MOUNT_POINT/vmbr1_selected_latest.pcap" "$DEST_DIR/vmbr1_${LABEL}_${TIMESTAMP}.pcap"
        echo "  -> Saved vmbr1_${LABEL}_${TIMESTAMP}.pcap"
    fi
    
    # 3. Unmount immediately to free up SSH resources
    sudo umount -l "$MOUNT_POINT"
    
    # 4. Wait for the server to generate the next snapshot
    if [ $i -lt $DURATION_MINUTES ]; then
        echo "  -> Waiting 60 seconds for the next snapshot rollover..."
        sleep 60
    fi
done

echo "=========================================="
echo " Harvesting complete. Files are in $DEST_DIR"
echo "=========================================="
