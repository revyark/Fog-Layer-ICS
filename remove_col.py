import pandas as pd
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "sensor_data.csv"

df = pd.read_csv(path)
print(f"Removed column: '{df.columns[-1]}'")

df = df.iloc[:, :-1]
df.to_csv(path, index=False)

print(f"Done. Saved to {path}  ({df.shape[1]} columns remaining)")