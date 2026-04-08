import pandas as pd
import os

benign_path = "/home/abdul/DigitalTwin/TAD-PETA/TAD/data/benign_traffic_advanced.csv"
attack_path = "/home/abdul/DigitalTwin/TAD-PETA/TAD/data/attack_traffic_advanced.csv"
out_dir = "/home/abdul/DigitalTwin/TAD-PETA/TAD/data"

print("Loading benign data...")
df_benign = pd.read_csv(benign_path)
b_count = len(df_benign)

print(f"Benign records: {b_count}")

# Calculate needed attack records to achieve the ratios
# Ratio = B / (B + A)
# 50/50 -> B = A
a_50 = b_count 
# 75/25 -> A = B * (25 / 75)
a_25 = int(b_count * (25.0 / 75.0))
# 95/05 -> A = B * (5 / 95)
a_05 = int(b_count * (5.0 / 95.0))

print(f"Target Attack counts - 50%: {a_50}, 25%: {a_25}, 5%: {a_05}")

print("Loading attack data... (This might take a minute due to its 750MB size)")
# Load attack data
df_attack = pd.read_csv(attack_path)

# Shuffle attack data to get random samples
print("Shuffling attack data...")
df_attack_sampled = df_attack.sample(frac=1, random_state=42).reset_index(drop=True)

print("Creating dataset 50/50 (50% Benign, 50% Attack)...")
df_50_50 = pd.concat([df_benign, df_attack_sampled.iloc[:a_50]]).sample(frac=1, random_state=42).reset_index(drop=True)
df_50_50.to_csv(os.path.join(out_dir, "dataset_50_50.csv"), index=False)

print("Creating dataset 75/25 (75% Benign, 25% Attack)...")
df_75_25 = pd.concat([df_benign, df_attack_sampled.iloc[:a_25]]).sample(frac=1, random_state=42).reset_index(drop=True)
df_75_25.to_csv(os.path.join(out_dir, "dataset_75_25.csv"), index=False)

print("Creating dataset 95/05 (95% Benign, 5% Attack)...")
df_95_05 = pd.concat([df_benign, df_attack_sampled.iloc[:a_05]]).sample(frac=1, random_state=42).reset_index(drop=True)
df_95_05.to_csv(os.path.join(out_dir, "dataset_95_05.csv"), index=False)

print("Done! Check the TAD/data directory for the new downsampled CSVs.")
