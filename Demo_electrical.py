from data_genarator import SimpleDataGenerator

print("="*70)
print("SIMPLE BUSINESS DATA GENERATOR")
print("="*70)

gen = SimpleDataGenerator(seed=42)

columns = {
    'station_id': 'id',
    'timestamp': 'timestamp',
    'voltage': 'voltage 110-240',
    'current': 'current 0-50',
    'status': ['Normal', 'Warning', 'Critical']
}


# Loop
df = gen.generate(rows=200, columns=columns, output_file='Electrical_Data.csv')
print(df.head())
