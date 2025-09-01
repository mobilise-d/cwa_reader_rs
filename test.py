from cwa_reader_rs import read_header, read_cwa_file
import pandas as pd

print("Testing CWA Reader...")

# Test header reading
try:
    print("1. Reading header...")
    header = read_header("/home/arne/Downloads/ax6_example_files/6014744_24031_T1_AX6_2021-08-11_00_00_00.cwa")
    print("Header fields:")
    for key, value in header.items():
        print(f"  {key}: {value}")
    print()
except Exception as e:
    print(f"Header error: {e}")

# Test data reading
try:
    print("2. Reading data (first 10 blocks)...")
    data = read_cwa_file("/home/arne/Downloads/ax6_example_files/6014744_24031_T1_AX6_2021-08-11_00_00_00.cwa",  include_magnetometer=False, include_temperature=True, include_light=False, include_battery=False)
    
    # Convert to pandas DataFrame
    print("\n3. Converting to pandas DataFrame...")
    df = pd.DataFrame(data)
    
    # Convert timestamp from microseconds to datetime
    df['datetime'] = pd.to_datetime(df['timestamp'], unit='us')
    df['date'] = df['datetime'].dt.date
    
    print(f"DataFrame shape: {df.shape}")
    print(f"Columns: {list(df.columns)}")

    # Find the start of 
    print("\nFirst 5 rows of each date:")
    for date in df['date'].unique():
        print(f"\nDate: {date}")
        print(df[df['date'] == date].head())
    
    print("\nData types:")
    print(df.dtypes)
    
except Exception as e:
    print(f"Data reading error: {e}")
    import traceback
    traceback.print_exc()