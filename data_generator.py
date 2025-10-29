import pandas as pd
import numpy as np
from datetime import datetime, timedelta

class SimpleDataGenerator:
    def __init__(self, seed=42):
        """Initialize with optional seed for reproducibility"""
        self.seed = seed
        np.random.seed(seed)
        
    def generate(self, rows, columns, output_file=None, table_name=None):
        data = {}
        
        for col_name, col_def in columns.items():
            data[col_name] = self._generate_column(col_name, col_def, rows)
        
        df = pd.DataFrame(data)
        
        # Save if requested
        if output_file:
            if output_file.endswith('.sql'):
                self._save_as_sql(df, output_file, table_name)
            else:
                df.to_csv(output_file, index=False)
                print(f"✓ Saved {rows:,} rows to {output_file}")
        
        return df
        
    def _generate_column(self, name, definition, rows):
        """Generate a single column based on its definition"""
        
        # ID columns
        if definition == 'id':
            return [f"{name.upper()[:3]}{i:06d}" for i in range(1, rows + 1)]
        
        # List of categories
        if isinstance(definition, list):
            return np.random.choice(definition, size=rows)
        
        # Parse string definitions
        if isinstance(definition, str):
            parts = definition.lower().split()
            
            # Dates: 'date 2020-2024' or just 'date'
            if parts[0] == 'date':
                if len(parts) > 1:
                    years = parts[1].split('-')
                    start = datetime(int(years[0]), 1, 1)
                    end = datetime(int(years[1]), 12, 31)
                else:
                    start = datetime(2020, 1, 1)
                    end = datetime(2025, 10, 31)
                
                days_diff = (end - start).days
                random_days = np.random.randint(0, days_diff, size=rows)
                return [start + timedelta(days=int(d)) for d in random_days]
            
            # Integers: 'int 18-65' or 'int 0-100'
            if parts[0] == 'int':
                if len(parts) > 1:
                    min_max = parts[1].split('-')
                    min_val = int(min_max[0])
                    max_val = int(min_max[1])
                else:
                    min_val, max_val = 0, 100
                return np.random.randint(min_val, max_val + 1, size=rows)
            
            # Floats: 'float 0-1' or 'float 0-100'
            if parts[0] == 'float':
                if len(parts) > 1:
                    min_max = parts[1].split('-')
                    min_val = float(min_max[0])
                    max_val = float(min_max[1])
                else:
                    min_val, max_val = 0.0, 1.0
                values = np.random.uniform(min_val, max_val, size=rows)
                return np.round(values, 2)
            
            # Money: 'money 10000-100000' (realistic income/prices)
            if parts[0] == 'money':
                if len(parts) > 1:
                    min_max = parts[1].split('-')
                    min_val = float(min_max[0])
                    max_val = float(min_max[1])
                else:
                    min_val, max_val = 1000, 100000
                
                # Use lognormal for realistic money distribution
                mean = (min_val + max_val) / 2
                values = np.random.lognormal(np.log(mean), 0.5, size=rows)
                values = np.clip(values, min_val, max_val)
                return np.round(values, 2)
            
            # Boolean: 'bool 30%' means 30% True
            if parts[0] == 'bool':
                if len(parts) > 1:
                    prob = float(parts[1].rstrip('%')) / 100
                else:
                    prob = 0.5
                return np.random.random(rows) < prob
            
            # Email
            if parts[0] == 'email':
                domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'company.com']
                return [f"user{i}@{np.random.choice(domains)}" for i in range(rows)]
            
            # Phone
            if parts[0] == 'phone':
                return [f"{np.random.randint(200, 999)}-{np.random.randint(200, 999)}-{np.random.randint(1000, 9999)}" 
                       for _ in range(rows)]
             # Current: 'current 0-100' (Amperes)
            if parts[0] == 'current':
                if len(parts) > 1:
                    min_max = parts[1].split('-')
                    min_val = float(min_max[0])
                    max_val = float(min_max[1])
                else:
                    min_val, max_val = 0.0, 10.0
                values = np.random.uniform(min_val, max_val, size=rows)
                return np.round(values, 2)

            # Temperature: 'temperature 15-35' (Celsius by default)
            if parts[0] == 'temperature':
                if len(parts) > 1:
                    min_max = parts[1].split('-')
                    min_val = float(min_max[0])
                    max_val = float(min_max[1])
                else:
                    min_val, max_val = 15.0, 35.0  # Room temperature range
                # Add some realistic fluctuation using normal distribution
                mean = (min_val + max_val) / 2
                std = (max_val - min_val) / 6
                values = np.random.normal(mean, std, size=rows)
                values = np.clip(values, min_val, max_val)
                return np.round(values, 2)
            
            # Voltage: 'voltage 110-240' (Volts)
            if parts[0] == 'voltage':
                if len(parts) > 1:
                    min_max = parts[1].split('-')
                    min_val = float(min_max[0])
                    max_val = float(min_max[1])
                else:
                    min_val, max_val = 110.0, 240.0  # Common voltage range
                values = np.random.uniform(min_val, max_val, size=rows)
                return np.round(values, 2)
            
            # Timestamp: 'timestamp 2024-01-01 2024-12-31' or just 'timestamp'
            if parts[0] == 'timestamp':
                if len(parts) >= 3:
                    start = datetime.strptime(parts[1], '%Y-%m-%d')
                    end = datetime.strptime(parts[2], '%Y-%m-%d')
                else:
                    start = datetime(2024, 1, 1)
                    end = datetime.now()
                
                # Generate random timestamps
                time_diff = (end - start).total_seconds()
                random_seconds = np.random.randint(0, int(time_diff), size=rows)
                timestamps = [start + timedelta(seconds=int(s)) for s in random_seconds]
                return timestamps
        
        # Default: random integers
        return np.random.randint(0, 100, size=rows)

    def _save_as_sql(self, df, output_file, table_name=None):
        """Save DataFrame as SQL INSERT statements"""
        
        # Extract table name from filename if not provided
        if table_name is None:
            table_name = output_file.replace('.sql', '').replace('\\', '/').split('/')[-1]
        
        with open(output_file, 'w') as f:
            # Write header comment
            f.write(f"-- SQL Insert Statements for {table_name}\n")
            f.write(f"-- Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"-- Rows: {len(df):,}\n\n")
            
            # Write CREATE TABLE statement
            f.write(f"-- Create table (adjust data types as needed)\n")
            f.write(f"CREATE TABLE IF NOT EXISTS {table_name} (\n")
            
            for i, (col, dtype) in enumerate(zip(df.columns, df.dtypes)):
                sql_type = self._pandas_to_sql_type(dtype)
                comma = "," if i < len(df.columns) - 1 else ""
                f.write(f"    {col} {sql_type}{comma}\n")
            
            f.write(f");\n\n")
            
            # Write INSERT statements in batches
            f.write(f"-- Insert data\n")
            batch_size = 100
            
            for batch_start in range(0, len(df), batch_size):
                batch_end = min(batch_start + batch_size, len(df))
                batch_df = df.iloc[batch_start:batch_end]
                
                f.write(f"INSERT INTO {table_name} ({', '.join(df.columns)}) VALUES\n")
                
                for idx, row in batch_df.iterrows():
                    values = []
                    for val in row:
                        if pd.isna(val):
                            values.append('NULL')
                        elif isinstance(val, str):
                            # Escape single quotes in strings
                            escaped = str(val).replace("'", "''")
                            values.append(f"'{escaped}'")
                        elif isinstance(val, (datetime, pd.Timestamp)):
                            values.append(f"'{val.strftime('%Y-%m-%d')}'")
                        elif isinstance(val, bool):
                            values.append('TRUE' if val else 'FALSE')
                        elif isinstance(val, (int, np.integer)):
                            values.append(str(int(val)))
                        elif isinstance(val, (float, np.floating)):
                            values.append(f"{val:.2f}")
                        else:
                            values.append(f"'{val}'")
                    
                    comma = "," if idx < batch_end - 1 else ";"
                    f.write(f"    ({', '.join(values)}){comma}\n")
                
                f.write("\n")
        
        print(f"✓ Saved {len(df):,} rows to {output_file} (SQL format)")
        print(f"  Table name: {table_name}")
    
    def _pandas_to_sql_type(self, dtype):
        """Convert pandas dtype to SQL type"""
        dtype_str = str(dtype)
        
        if 'int' in dtype_str:
            return 'INTEGER'
        elif 'float' in dtype_str:
            return 'DECIMAL(10,2)'
        elif 'bool' in dtype_str:
            return 'BOOLEAN'
        elif 'datetime' in dtype_str:
            return 'DATE'
        else:
            return 'VARCHAR(255)'    

