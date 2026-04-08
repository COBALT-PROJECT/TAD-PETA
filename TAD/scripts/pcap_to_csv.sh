#!/bin/bash

# Configuration
DATA_DIR="/home/abdul/DigitalTwin/TAD-PETA/TAD/data"
OUTPUT_FILE="/home/abdul/DigitalTwin/TAD-PETA/TAD/data/benign_traffic.csv"

# Write headers to the CSV
echo "timestamp,frame_len,src_ip,dst_ip,protocol,src_port,dst_port,tcp_flags,label" > "$OUTPUT_FILE"

echo "Processing PCAP files..."

# Loop through all benign pcap files in the directory
for pcap in "$DATA_DIR"/*_benign_*.pcap; do
    # Ensure it's a file
    if [ -f "$pcap" ]; then
        echo "Extracting features from: $(basename "$pcap")"
        
        # Use tshark to extract specific fields
        # fields: frame.time_epoch (timestamp), frame.len (total packet length), 
        # ip.src (source IP), ip.dst (destination IP), _ws.col.Protocol (protocol name)
        # tcp.srcport or udp.srcport (source port), tcp.dstport or udp.dstport (destination port)
        # tcp.flags.str (TCP flags if applicable)
        
        tshark -r "$pcap" -T fields \
            -e frame.time_epoch \
            -e frame.len \
            -e ip.src \
            -e ip.dst \
            -e _ws.col.Protocol \
            -e tcp.srcport -e udp.srcport \
            -e tcp.dstport -e udp.dstport \
            -e tcp.flags.str \
            -E separator=, -E quote=n | \
        awk '
        BEGIN { FS=","; OFS="," }
        {
            # Format the output and fill empty fields
            ts = $1
            len = $2
            src_ip = $3 ? $3 : "None"
            dst_ip = $4 ? $4 : "None"
            proto = $5 ? $5 : "Unknown"
            
            # Use TCP port if available, else UDP, else 0
            src_port = $6 ? $6 : ($7 ? $7 : "0")
            dst_port = $8 ? $8 : ($9 ? $9 : "0")
            
            tcp_flags = $10 ? $10 : "None"
            
            # Label 0 for benign
            label = 0
            
            print ts, len, src_ip, dst_ip, proto, src_port, dst_port, tcp_flags, label
        }
        ' >> "$OUTPUT_FILE"
    fi
done

echo "Extraction complete! Data saved to: $OUTPUT_FILE"
echo "Total rows:"
wc -l "$OUTPUT_FILE"
