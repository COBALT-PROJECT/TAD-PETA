# Overview
This workflow describes how to utilize the new bash scripts to harvest PCAP data from isolated Virtual Machines, transform that traffic into CSV feature datasets, and run the realtime orchestration monitor.

# Step 1: Harvest PCAP Data
Execute the harvester script to mount the remote Proxmox VM NFS share and copy over traffic captures locally. It will prompt for a label (`benign` or `attack`) and loop over the specified duration.

`./TAD/scripts/harvester.sh`

# Step 2: Transform PCAPs to CSV
Convert the raw PCAP files into structured CSV formats to act as feature sets for the Machine Learning training pipeline.

For Benign traffic:
`./TAD/scripts/pcap_to_csv.sh`
This generates `TAD/data/benign_traffic.csv` with standard telemetry.

For Attack traffic:
`./TAD/scripts/pcap_to_csv_advanced.sh`
This generates `TAD/data/attack_traffic_advanced.csv` extracting specific deep packet inspection properties (TTL, Window Size, SEQ/ACK flags) with forced label `1`.

# Step 3: Run the Monitor
Run the orchestration logic which serves as a stream processor mapping the results from the inference pipeline into actionable events sent to PETA.

`python3 TAD/scripts/realtime_monitor.py --peta-url http://localhost:8000/sdt-topo/`

To test the integration loop manually without requiring an active NFS harvest, execute it in simulation mode:
`python3 TAD/scripts/realtime_monitor.py --peta-url http://localhost:8000/sdt-topo/ --simulate`
