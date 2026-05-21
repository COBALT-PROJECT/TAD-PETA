#!/bin/bash

# Configuration
INPUT_DIR="/home/abdul/DigitalTwin/TAD-PETA/TAD/data"
OUTPUT_FILE="$INPUT_DIR/attack_traffic_multiclass.csv"

echo "Creating multi-class CSV with extended features..."

# Create CSV Header
echo "timestamp,frame_len,src_ip,dst_ip,protocol,src_port,dst_port,tcp_flags,ip_ttl,tcp_window_size,tcp_seq,tcp_ack,label" > "$OUTPUT_FILE"

# Process all PCAP files — order: specific types first, generic last to avoid mislabeling
for pcap in "$INPUT_DIR"/*_bruteforce_*.pcap "$INPUT_DIR"/*_dos_*.pcap "$INPUT_DIR"/*_scan_*.pcap "$INPUT_DIR"/*_benign_*.pcap "$INPUT_DIR"/*_attack_*.pcap; do
    if [ -f "$pcap" ]; then
        echo "Processing $pcap..."
        # Derive multi-class label from filename
        if [[ "$pcap" == *"_benign_"* ]]; then
            LABEL="benign"
        elif [[ "$pcap" == *"_bruteforce_"* ]]; then
            LABEL="bruteforce"
        elif [[ "$pcap" == *"_dos_"* ]]; then
            LABEL="dos"
        elif [[ "$pcap" == *"_scan_"* ]]; then
            LABEL="scan"
        else
            LABEL="attack"
        fi
        
        tshark -r "$pcap" -T fields \
            -e frame.time_epoch \
            -e frame.len \
            -e ip.src \
            -e ip.dst \
            -e _ws.col.Protocol \
            -e tcp.srcport \
            -e tcp.dstport \
            -e tcp.flags \
            -e ip.ttl \
            -e tcp.window_size \
            -e tcp.seq \
            -e tcp.ack \
            -E separator=, -E occurrence=f | \
            awk -v lbl="$LABEL" 'BEGIN {FS=","; OFS=","} {
                # Handle empty fields for non-TCP packets
                for(i=1; i<=NF; i++) {
                    if ($i == "") $i="0"
                }
                print $0, lbl
            }' >> "$OUTPUT_FILE"
    fi
done

echo "Multi-class feature extraction complete. Output saved to $OUTPUT_FILE"
