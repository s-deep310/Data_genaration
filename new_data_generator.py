"""
Autonomous Business Data Generator
Generates realistic synthetic data for ANY business use case with intelligent schema inference,
scenario simulation, noise injection, and constraint enforcement.
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
import warnings

warnings.filterwarnings('ignore')


class BusinessDataGenerator:

    def __init__(self, seed: int = 42):
        """Initialize generator with seed for reproducibility"""
        self.seed = seed
        np.random.seed(seed)
        self.report_lines = []
        self.assumptions = []
        self.violations_repaired = {}
    
    def generate(self,
                 use_case: str,
                 rows: int = 100,
                 scenario: str = 'average_case',
                 noise_level: float = 0.0,
                 train_test_split: Optional[Dict[str, float]] = None,
                 output_file: Optional[str] = None) -> pd.DataFrame:
        """
        Generate synthetic data for any business use case.
        
        Parameters:
        -----------
        use_case : str
            Description of your business use case. Examples:
            - "customer churn prediction"
            - "sales forecasting" 
            - "loan default modeling"
            - "employee retention"
            - "product recommendation"
            
        rows : int
            Number of rows to generate (default: 1000)
            
        scenario : str
            'best_case', 'average_case', or 'worst_case'
            - best_case: optimal conditions (higher revenue, lower churn, tight variance)
            - average_case: typical business conditions
            - worst_case: stress conditions (higher churn, delays, anomalies)
            
        noise_level : float
            0.0 to 1.0 - controls data quality issues
            - 0.0: clean data
            - 0.3: realistic noise (recommended)
            - 0.5+: high noise (testing robustness)
            
        train_test_split : dict, optional
            {'train': 0.7, 'valid': 0.15, 'test': 0.15}
            
        output_file : str, optional
            CSV filename to save (e.g., 'data.csv')
            
        Returns:
        --------
        pd.DataFrame with generated data
        """
        
        print(f"\n{'='*70}")
        print(f"AUTONOMOUS BUSINESS DATA GENERATOR")
        print(f"{'='*70}")
        print(f"Use Case: {use_case}")
        print(f"Rows: {rows:,}")
        print(f"Scenario: {scenario}")
        print(f"Noise Level: {noise_level:.1%}")
        print(f"{'='*70}\n")
        
        # Step 1: Infer schema from use case
        print("Step 1: Inferring schema from use case...")
        schema = self._infer_schema(use_case)
        print(f"  ✓ Identified {len(schema)} key features")
        
        # Step 2: Generate base data
        print("\nStep 2: Generating base data...")
        df = self._generate_base_data(rows, schema, scenario)
        print(f"  ✓ Generated {len(df)} rows")
        
        # Step 3: Apply correlations
        print("\nStep 3: Applying cross-field correlations...")
        df = self._apply_correlations(df, schema, scenario)
        print(f"  ✓ Applied correlations")
        
        # Step 4: Generate target variable
        if 'target_config' in schema:
            print("\nStep 4: Generating target variable...")
            df = self._generate_target(df, schema, scenario)
            target_name = schema['target_config']['name']
            if target_name in df.columns:
                if df[target_name].dtype == bool:
                    target_rate = df[target_name].mean()
                    print(f"  ✓ Target '{target_name}': {target_rate:.1%}")
                else:
                    target_mean = df[target_name].mean()
                    print(f"  ✓ Target '{target_name}': ${target_mean:.2f} avg")
        
        # Step 5: Apply noise
        if noise_level > 0:
            print(f"\nStep 5: Injecting noise (level: {noise_level:.1%})...")
            df = self._inject_noise(df, noise_level)
            print(f"  ✓ Noise applied")
        
        # Step 6: Create splits
        if train_test_split:
            print("\nStep 6: Creating train/valid/test splits...")
            df = self._create_splits(df, train_test_split, schema)
            print(f"  ✓ Splits created")
        
        # Step 7: Validate and repair
        print("\nStep 7: Validating data...")
        df = self._validate_and_repair(df, schema)
        print(f"  ✓ Validation complete")
        
        # Step 8: Generate report
        print("\nStep 8: Generating report...")
        self._generate_report(use_case, df, schema, scenario, noise_level)
        
        # Step 9: Export
        if output_file:
            df.to_csv(output_file, index=False)
            print(f"\n✓ Saved to: {output_file}")
        
        # Print report
        print(f"\n{'='*70}")
        print("GENERATION REPORT")
        print(f"{'='*70}")
        for line in self.report_lines:
            print(line)
        
        print(f"\n{'='*70}")
        print("✓ DATA GENERATION COMPLETE")
        print(f"{'='*70}\n")
        
        return df
    
    def _infer_schema(self, use_case: str) -> Dict:
        """Intelligently infer schema from use case description"""
        
        use_case_lower = use_case.lower()
        
        # Customer churn use cases
        if any(word in use_case_lower for word in ['churn', 'retention', 'attrition']):
            return self._schema_churn()
        
        # Sales/revenue use cases
        elif any(word in use_case_lower for word in ['sales', 'revenue', 'forecasting']):
            return self._schema_sales()
        
        # Loan/credit use cases
        elif any(word in use_case_lower for word in ['loan', 'credit', 'default', 'lending']):
            return self._schema_loan_default()
        
        # Employee/HR use cases
        elif any(word in use_case_lower for word in ['employee', 'hr', 'turnover', 'hiring']):
            return self._schema_employee()
        
        # Marketing/conversion use cases
        elif any(word in use_case_lower for word in ['marketing', 'conversion', 'campaign', 'lead']):
            return self._schema_marketing()
        
        # E-commerce use cases
        elif any(word in use_case_lower for word in ['ecommerce', 'e-commerce', 'product', 'purchase']):
            return self._schema_ecommerce()
        
        # Fraud detection use cases
        elif any(word in use_case_lower for word in ['fraud', 'anomaly', 'suspicious']):
            return self._schema_fraud()
        
        # IoT/sensor use cases
        elif any(word in use_case_lower for word in ['iot', 'sensor', 'device', 'equipment']):
            return self._schema_iot()
        
        # Default: generic business schema
        else:
            self.assumptions.append(f"Could not match use case to template, using generic business schema")
            return self._schema_generic()
    
    def _schema_churn(self) -> Dict:
        """Schema for customer churn prediction"""
        self.assumptions.append("Inferred: Customer churn prediction use case")
        return {
            'customer_id': {'type': 'id', 'prefix': 'CUST'},
            'signup_date': {'type': 'date', 'range': ['2020-01-01', '2025-10-31']},
            'age': {'type': 'int', 'dist': 'normal', 'mean': 38, 'std': 12, 'min': 18, 'max': 80},
            'tenure_months': {'type': 'int', 'dist': 'gamma', 'shape': 2, 'scale': 12, 'min': 1, 'max': 120},
            'monthly_charges': {'type': 'money', 'min': 20, 'max': 200},
            'total_charges': {'type': 'money', 'min': 100, 'max': 15000},
            'contract_type': {'type': 'category', 'values': ['Month-to-Month', '1-Year', '2-Year'], 
                            'probs': [0.5, 0.3, 0.2]},
            'payment_method': {'type': 'category', 'values': ['Auto', 'Manual'], 'probs': [0.6, 0.4]},
            'support_tickets': {'type': 'int', 'dist': 'poisson', 'lambda': 2, 'min': 0, 'max': 30},
            'service_calls': {'type': 'int', 'dist': 'poisson', 'lambda': 1.5, 'min': 0, 'max': 20},
            'target_config': {
                'name': 'churned',
                'type': 'classification',
                'target_rate': 0.25,
                'features': {
                    'tenure_months': -0.5,
                    'support_tickets': 0.4,
                    'contract_type': -0.3,
                    'monthly_charges': 0.2
                }
            }
        }
    
    def _schema_sales(self) -> Dict:
        """Schema for sales forecasting"""
        self.assumptions.append("Inferred: Sales forecasting use case")
        return {
            'transaction_id': {'type': 'id', 'prefix': 'TXN'},
            'transaction_date': {'type': 'date', 'range': ['2023-01-01', '2024-12-31']},
            'customer_segment': {'type': 'category', 'values': ['Enterprise', 'SMB', 'Consumer'], 
                                'probs': [0.2, 0.4, 0.4]},
            'product_category': {'type': 'category', 
                                'values': ['Electronics', 'Clothing', 'Home', 'Sports', 'Books'],
                                'probs': [0.25, 0.25, 0.2, 0.15, 0.15]},
            'quantity': {'type': 'int', 'dist': 'poisson', 'lambda': 3, 'min': 1, 'max': 20},
            'unit_price': {'type': 'money', 'min': 10, 'max': 2000},
            'discount_pct': {'type': 'float', 'dist': 'beta', 'alpha': 2, 'beta': 5, 'min': 0, 'max': 50},
            'shipping_days': {'type': 'int', 'dist': 'normal', 'mean': 5, 'std': 2, 'min': 1, 'max': 30},
            'region': {'type': 'category', 'values': ['North', 'South', 'East', 'West'], 
                      'probs': [0.3, 0.25, 0.25, 0.2]},
            'target_config': {
                'name': 'revenue',
                'type': 'regression',
                'compute': 'quantity * unit_price * (1 - discount_pct/100)'
            }
        }
    
    def _schema_loan_default(self) -> Dict:
        """Schema for loan default prediction"""
        self.assumptions.append("Inferred: Loan default prediction use case")
        return {
            'loan_id': {'type': 'id', 'prefix': 'LOAN'},
            'application_date': {'type': 'date', 'range': ['2020-01-01', '2024-12-31']},
            'loan_amount': {'type': 'money', 'min': 5000, 'max': 500000},
            'loan_term_months': {'type': 'int', 'dist': 'category_int', 'values': [12, 24, 36, 48, 60],
                                'probs': [0.1, 0.2, 0.3, 0.25, 0.15]},
            'interest_rate': {'type': 'float', 'dist': 'normal', 'mean': 8.5, 'std': 3, 'min': 3, 'max': 25},
            'credit_score': {'type': 'int', 'dist': 'normal', 'mean': 680, 'std': 80, 'min': 300, 'max': 850},
            'annual_income': {'type': 'money', 'min': 25000, 'max': 500000},
            'debt_to_income': {'type': 'float', 'dist': 'beta', 'alpha': 2, 'beta': 3, 'min': 0, 'max': 1},
            'employment_years': {'type': 'int', 'dist': 'gamma', 'shape': 2, 'scale': 3, 'min': 0, 'max': 40},
            'loan_purpose': {'type': 'category', 
                           'values': ['Home', 'Auto', 'Business', 'Education', 'Personal'],
                           'probs': [0.3, 0.25, 0.2, 0.15, 0.1]},
            'target_config': {
                'name': 'defaulted',
                'type': 'classification',
                'target_rate': 0.15,
                'features': {
                    'credit_score': -0.8,
                    'debt_to_income': 0.6,
                    'annual_income': -0.4,
                    'employment_years': -0.3
                }
            }
        }
    
    def _schema_employee(self) -> Dict:
        """Schema for employee retention/turnover"""
        self.assumptions.append("Inferred: Employee retention use case")
        return {
            'employee_id': {'type': 'id', 'prefix': 'EMP'},
            'hire_date': {'type': 'date', 'range': ['2015-01-01', '2024-12-31']},
            'department': {'type': 'category', 
                         'values': ['Engineering', 'Sales', 'Marketing', 'HR', 'Finance', 'Operations'],
                         'probs': [0.25, 0.2, 0.15, 0.1, 0.15, 0.15]},
            'job_level': {'type': 'category', 'values': ['Junior', 'Mid', 'Senior', 'Lead', 'Manager'],
                         'probs': [0.3, 0.3, 0.2, 0.1, 0.1]},
            'salary': {'type': 'money', 'min': 40000, 'max': 250000},
            'age': {'type': 'int', 'dist': 'normal', 'mean': 35, 'std': 10, 'min': 22, 'max': 65},
            'years_at_company': {'type': 'int', 'dist': 'gamma', 'shape': 2, 'scale': 2, 'min': 0, 'max': 30},
            'performance_score': {'type': 'float', 'dist': 'normal', 'mean': 3.5, 'std': 0.8, 'min': 1, 'max': 5},
            'training_hours': {'type': 'int', 'dist': 'gamma', 'shape': 2, 'scale': 10, 'min': 0, 'max': 200},
            'remote': {'type': 'bool', 'prob': 0.6},
            'target_config': {
                'name': 'will_leave',
                'type': 'classification',
                'target_rate': 0.18,
                'features': {
                    'years_at_company': -0.4,
                    'performance_score': -0.5,
                    'salary': -0.3,
                    'training_hours': -0.2
                }
            }
        }
    
    def _schema_marketing(self) -> Dict:
        """Schema for marketing conversion"""
        self.assumptions.append("Inferred: Marketing conversion use case")
        return {
            'lead_id': {'type': 'id', 'prefix': 'LEAD'},
            'created_date': {'type': 'date', 'range': ['2024-01-01', '2024-12-31']},
            'source': {'type': 'category', 
                      'values': ['Google Ads', 'Facebook', 'LinkedIn', 'Email', 'Referral', 'Organic'],
                      'probs': [0.25, 0.2, 0.15, 0.15, 0.15, 0.1]},
            'lead_score': {'type': 'int', 'dist': 'beta_scaled', 'alpha': 2, 'beta': 5, 'min': 0, 'max': 100},
            'page_views': {'type': 'int', 'dist': 'poisson', 'lambda': 8, 'min': 1, 'max': 100},
            'time_on_site_min': {'type': 'float', 'dist': 'gamma', 'shape': 2, 'scale': 5, 'min': 0, 'max': 120},
            'email_opens': {'type': 'int', 'dist': 'poisson', 'lambda': 3, 'min': 0, 'max': 30},
            'downloads': {'type': 'int', 'dist': 'poisson', 'lambda': 1, 'min': 0, 'max': 10},
            'company_size': {'type': 'category', 'values': ['1-10', '11-50', '51-200', '201-500', '500+'],
                           'probs': [0.3, 0.3, 0.2, 0.1, 0.1]},
            'budget': {'type': 'money', 'min': 1000, 'max': 100000},
            'target_config': {
                'name': 'converted',
                'type': 'classification',
                'target_rate': 0.12,
                'features': {
                    'lead_score': 0.7,
                    'page_views': 0.5,
                    'email_opens': 0.4,
                    'downloads': 0.6
                }
            }
        }
    
    def _schema_ecommerce(self) -> Dict:
        """Schema for e-commerce"""
        self.assumptions.append("Inferred: E-commerce use case")
        return {
            'order_id': {'type': 'id', 'prefix': 'ORD'},
            'order_date': {'type': 'date', 'range': ['2024-01-01', '2024-12-31']},
            'customer_age': {'type': 'int', 'dist': 'normal', 'mean': 35, 'std': 12, 'min': 18, 'max': 80},
            'customer_type': {'type': 'category', 'values': ['New', 'Returning'], 'probs': [0.3, 0.7]},
            'product_category': {'type': 'category',
                                'values': ['Electronics', 'Clothing', 'Home', 'Beauty', 'Sports'],
                                'probs': [0.25, 0.3, 0.2, 0.15, 0.1]},
            'items_in_cart': {'type': 'int', 'dist': 'poisson', 'lambda': 4, 'min': 1, 'max': 20},
            'cart_value': {'type': 'money', 'min': 10, 'max': 5000},
            'shipping_cost': {'type': 'money', 'min': 0, 'max': 50},
            'delivery_days': {'type': 'int', 'dist': 'normal', 'mean': 5, 'std': 2, 'min': 1, 'max': 30},
            'payment_method': {'type': 'category',
                             'values': ['Credit Card', 'Debit Card', 'PayPal', 'Cash'],
                             'probs': [0.4, 0.3, 0.25, 0.05]},
            'target_config': {
                'name': 'purchased',
                'type': 'classification',
                'target_rate': 0.70,
                'features': {
                    'cart_value': 0.3,
                    'items_in_cart': 0.4,
                    'customer_type': -0.5,  # New customers less likely
                    'shipping_cost': -0.2
                }
            }
        }
    
    def _schema_fraud(self) -> Dict:
        """Schema for fraud detection"""
        self.assumptions.append("Inferred: Fraud detection use case")
        return {
            'transaction_id': {'type': 'id', 'prefix': 'TXN'},
            'timestamp': {'type': 'timestamp', 'range': ['2024-01-01', '2024-12-31']},
            'amount': {'type': 'money', 'min': 1, 'max': 10000},
            'merchant_category': {'type': 'category',
                                 'values': ['Retail', 'Restaurant', 'Gas', 'Online', 'Travel'],
                                 'probs': [0.3, 0.25, 0.2, 0.15, 0.1]},
            'transaction_type': {'type': 'category', 'values': ['Purchase', 'Withdrawal', 'Transfer'],
                                'probs': [0.7, 0.2, 0.1]},
            'distance_from_home_km': {'type': 'float', 'dist': 'gamma', 'shape': 2, 'scale': 10, 'min': 0, 'max': 5000},
            'time_since_last_txn_hours': {'type': 'float', 'dist': 'gamma', 'shape': 2, 'scale': 5, 'min': 0, 'max': 720},
            'failed_attempts_24h': {'type': 'int', 'dist': 'poisson', 'lambda': 0.5, 'min': 0, 'max': 20},
            'is_international': {'type': 'bool', 'prob': 0.1},
            'device_type': {'type': 'category', 'values': ['Mobile', 'Desktop', 'ATM'], 'probs': [0.5, 0.4, 0.1]},
            'target_config': {
                'name': 'is_fraud',
                'type': 'classification',
                'target_rate': 0.02,  # Low fraud rate
                'features': {
                    'amount': 0.5,
                    'distance_from_home_km': 0.6,
                    'failed_attempts_24h': 0.7,
                    'is_international': 0.4
                }
            }
        }
    
    def _schema_iot(self) -> Dict:
        """Schema for IoT/sensor data"""
        self.assumptions.append("Inferred: IoT/sensor monitoring use case")
        return {
            'device_id': {'type': 'id', 'prefix': 'DEV'},
            'timestamp': {'type': 'timestamp', 'range': ['2024-01-01', '2024-12-31']},
            'temperature': {'type': 'float', 'dist': 'normal', 'mean': 25, 'std': 5, 'min': -20, 'max': 60},
            'voltage': {'type': 'float', 'dist': 'normal', 'mean': 3.3, 'std': 0.2, 'min': 2.5, 'max': 4.0},
            'current': {'type': 'float', 'dist': 'normal', 'mean': 1.5, 'std': 0.5, 'min': 0, 'max': 5},
            'humidity': {'type': 'int', 'dist': 'normal', 'mean': 50, 'std': 15, 'min': 20, 'max': 90},
            'signal_strength': {'type': 'int', 'dist': 'normal', 'mean': -60, 'std': 15, 'min': -100, 'max': -30},
            'battery_level': {'type': 'int', 'dist': 'uniform', 'min': 0, 'max': 100},
            'device_type': {'type': 'category', 'values': ['Sensor', 'Gateway', 'Controller'], 
                          'probs': [0.7, 0.2, 0.1]},
            'location': {'type': 'category', 'values': ['Zone_A', 'Zone_B', 'Zone_C', 'Zone_D'],
                        'probs': [0.4, 0.3, 0.2, 0.1]},
            'target_config': {
                'name': 'needs_maintenance',
                'type': 'classification',
                'target_rate': 0.10,
                'features': {
                    'temperature': 0.4,
                    'voltage': -0.5,
                    'battery_level': -0.6,
                    'signal_strength': 0.3
                }
            }
        }
    
    def _schema_generic(self) -> Dict:
        """Generic business schema"""
        return {
            'record_id': {'type': 'id', 'prefix': 'REC'},
            'created_date': {'type': 'date', 'range': ['2023-01-01', '2024-12-31']},
            'category': {'type': 'category', 'values': ['A', 'B', 'C'], 'probs': [0.5, 0.3, 0.2]},
            'value': {'type': 'money', 'min': 0, 'max': 10000},
            'quantity': {'type': 'int', 'dist': 'poisson', 'lambda': 5, 'min': 0, 'max': 100},
            'score': {'type': 'float', 'dist': 'normal', 'mean': 50, 'std': 15, 'min': 0, 'max': 100},
            'target_config': {
                'name': 'target',
                'type': 'classification',
                'target_rate': 0.30,
                'features': {
                    'value': 0.5,
                    'quantity': 0.3,
                    'score': 0.4
                }
            }
        }
    
    def _generate_base_data(self, rows: int, schema: Dict, scenario: str) -> pd.DataFrame:
        """Generate base data for all columns"""
        data = {}
        
        for col_name, col_spec in schema.items():
            if col_name == 'target_config':
                continue
            
            col_type = col_spec['type']
            
            if col_type == 'id':
                data[col_name] = self._gen_id(rows, col_spec)
            elif col_type == 'date':
                data[col_name] = self._gen_date(rows, col_spec)
            elif col_type == 'timestamp':
                data[col_name] = self._gen_timestamp(rows, col_spec)
            elif col_type == 'int':
                data[col_name] = self._gen_int(rows, col_spec, scenario)
            elif col_type == 'float':
                data[col_name] = self._gen_float(rows, col_spec, scenario)
            elif col_type == 'money':
                data[col_name] = self._gen_money(rows, col_spec, scenario)
            elif col_type == 'category':
                data[col_name] = self._gen_category(rows, col_spec, scenario)
            elif col_type == 'bool':
                data[col_name] = self._gen_bool(rows, col_spec, scenario)
        
        return pd.DataFrame(data)
    
    def _gen_id(self, rows: int, spec: Dict) -> np.ndarray:
        """Generate unique IDs"""
        prefix = spec.get('prefix', 'ID')
        return np.array([f"{prefix}{i:06d}" for i in range(1, rows + 1)])
    
    def _gen_date(self, rows: int, spec: Dict) -> np.ndarray:
        """Generate dates"""
        date_range = spec.get('range', ['2023-01-01', '2024-12-31'])
        start = pd.to_datetime(date_range[0])
        end = pd.to_datetime(date_range[1])
        days = (end - start).days
        random_days = np.random.randint(0, days + 1, size=rows)
        return np.array([start + timedelta(days=int(d)) for d in random_days])
    
    def _gen_timestamp(self, rows: int, spec: Dict) -> np.ndarray:
        """Generate timestamps"""
        date_range = spec.get('range', ['2024-01-01', '2024-12-31'])
        start = pd.to_datetime(date_range[0])
        end = pd.to_datetime(date_range[1])
        seconds = (end - start).total_seconds()
        random_seconds = np.random.randint(0, int(seconds), size=rows)
        return np.array([start + timedelta(seconds=int(s)) for s in random_seconds])
    
    def _gen_int(self, rows: int, spec: Dict, scenario: str) -> np.ndarray:
        """Generate integers"""
        dist = spec.get('dist', 'uniform')
        min_val = spec.get('min', 0)
        max_val = spec.get('max', 100)
        
        mult = self._scenario_multiplier(scenario, spec)
        
        if dist == 'uniform':
            values = np.random.randint(min_val, max_val + 1, rows)
        elif dist == 'normal':
            mean = spec.get('mean', (min_val + max_val) / 2) * mult
            std = spec.get('std', (max_val - min_val) / 6)
            values = np.round(np.random.normal(mean, std, rows)).astype(int)
        elif dist == 'poisson':
            lam = spec.get('lambda', 5) * mult
            values = np.random.poisson(lam, rows)
        elif dist == 'gamma':
            shape = spec.get('shape', 2)
            scale = spec.get('scale', 1) * mult
            values = np.round(np.random.gamma(shape, scale, rows)).astype(int)
        elif dist == 'category_int':
            cat_values = spec.get('values', [1, 2, 3])
            probs = spec.get('probs', [1/len(cat_values)] * len(cat_values))
            values = np.random.choice(cat_values, size=rows, p=probs)
        elif dist == 'beta_scaled':
            alpha = spec.get('alpha', 2)
            beta = spec.get('beta', 5)
            beta_vals = np.random.beta(alpha, beta, rows)
            values = np.round(beta_vals * (max_val - min_val) + min_val).astype(int)
        else:
            values = np.random.randint(min_val, max_val + 1, rows)
        
        return np.clip(values, min_val, max_val)
    
    def _gen_float(self, rows: int, spec: Dict, scenario: str) -> np.ndarray:
        """Generate floats"""
        dist = spec.get('dist', 'uniform')
        min_val = spec.get('min', 0.0)
        max_val = spec.get('max', 1.0)
        
        mult = self._scenario_multiplier(scenario, spec)
        
        if dist == 'uniform':
            values = np.random.uniform(min_val, max_val, rows)
        elif dist == 'normal':
            mean = spec.get('mean', (min_val + max_val) / 2) * mult
            std = spec.get('std', (max_val - min_val) / 6)
            values = np.random.normal(mean, std, rows)
        elif dist == 'gamma':
            shape = spec.get('shape', 2)
            scale = spec.get('scale', 1) * mult
            values = np.random.gamma(shape, scale, rows)
        elif dist == 'beta':
            alpha = spec.get('alpha', 2)
            beta = spec.get('beta', 5)
            beta_vals = np.random.beta(alpha, beta, rows)
            values = beta_vals * (max_val - min_val) + min_val
        else:
            values = np.random.uniform(min_val, max_val, rows)
        
        values = np.clip(values, min_val, max_val)
        return np.round(values, 2)
    
    def _gen_money(self, rows: int, spec: Dict, scenario: str) -> np.ndarray:
        """Generate money values"""
        min_val = spec.get('min', 0)
        max_val = spec.get('max', 10000)
        
        mult = self._scenario_multiplier(scenario, spec)
        
        # Use lognormal for realistic money distribution
        mean = (min_val + max_val) / 2 * mult
        values = np.random.lognormal(np.log(max(mean, 1)), 0.5, rows)
        values = np.clip(values, min_val, max_val)
        return np.round(values, 2)
    
    def _gen_category(self, rows: int, spec: Dict, scenario: str) -> np.ndarray:
        """Generate categorical values"""
        values = spec.get('values', ['A', 'B', 'C'])
        probs = spec.get('probs', [1/len(values)] * len(values))
        
        # Adjust probabilities for scenario
        if scenario == 'worst_case' and len(probs) > 0:
            # Shift towards "worse" categories (typically last ones)
            probs = np.array(probs)
            probs = probs * np.linspace(1.2, 0.8, len(probs))
            probs = probs / probs.sum()
        elif scenario == 'best_case' and len(probs) > 0:
            # Shift towards "better" categories (typically first ones)
            probs = np.array(probs)
            probs = probs * np.linspace(0.8, 1.2, len(probs))
            probs = probs / probs.sum()
        
        return np.random.choice(values, size=rows, p=probs)
    
    def _gen_bool(self, rows: int, spec: Dict, scenario: str) -> np.ndarray:
        """Generate boolean values"""
        prob = spec.get('prob', 0.5)
        
        # Adjust for scenario
        if scenario == 'worst_case':
            prob *= 1.2
        elif scenario == 'best_case':
            prob *= 0.8
        
        prob = np.clip(prob, 0, 1)
        return np.random.random(rows) < prob
    
    def _scenario_multiplier(self, scenario: str, spec: Dict) -> float:
        """Get multiplier based on scenario"""
        if scenario == 'best_case':
            return spec.get('best_mult', 1.2)
        elif scenario == 'worst_case':
            return spec.get('worst_mult', 0.8)
        return 1.0
    
    def _apply_correlations(self, df: pd.DataFrame, schema: Dict, scenario: str) -> pd.DataFrame:
        """Apply cross-field correlations"""
        
        # Correlation: total_charges = monthly_charges * tenure_months (approximately)
        if 'total_charges' in df.columns and 'monthly_charges' in df.columns and 'tenure_months' in df.columns:
            noise = np.random.uniform(0.8, 1.2, len(df))
            df['total_charges'] = df['monthly_charges'] * df['tenure_months'] * noise
            df['total_charges'] = np.round(df['total_charges'], 2)
        
        # Correlation: revenue = quantity * unit_price * (1 - discount)
        if 'target_config' in schema:
            target_config = schema['target_config']
            if 'compute' in target_config:
                compute_expr = target_config['compute']
                # Parse and compute revenue
                if 'quantity * unit_price' in compute_expr:
                    if all(col in df.columns for col in ['quantity', 'unit_price']):
                        if 'discount_pct' in df.columns:
                            df['revenue'] = df['quantity'] * df['unit_price'] * (1 - df['discount_pct']/100)
                        else:
                            df['revenue'] = df['quantity'] * df['unit_price']
                        df['revenue'] = np.round(df['revenue'], 2)
        
        return df
    
    def _generate_target(self, df: pd.DataFrame, schema: Dict, scenario: str) -> pd.DataFrame:
        """Generate target variable using logistic model or computation"""
        target_config = schema['target_config']
        target_name = target_config['name']
        target_type = target_config.get('type', 'classification')
        
        # Regression target (computed from other columns)
        if target_type == 'regression':
            compute_expr = target_config.get('compute', '')
            if compute_expr:
                # Already computed in _apply_correlations
                return df
            else:
                # Simple regression target
                return df
        
        # Classification target
        if target_type == 'classification':
            features = target_config.get('features', {})
            target_rate = target_config.get('target_rate', 0.3)
            
            # Build logistic model
            z = np.zeros(len(df))
            
            for feature, weight in features.items():
                if feature in df.columns:
                    if df[feature].dtype == 'object' or df[feature].dtype == 'bool':
                        # Categorical: one-hot encode
                        encoded = pd.get_dummies(df[feature], prefix=feature, drop_first=True)
                        for col in encoded.columns:
                            z += encoded[col].values * weight * 0.5
                    else:
                        # Numeric: normalize
                        col_mean = df[feature].mean()
                        col_std = df[feature].std()
                        if col_std > 0:
                            normalized = (df[feature] - col_mean) / col_std
                            z += normalized.values * weight
            
            # Scenario adjustment
            if scenario == 'worst_case':
                z += 0.5  # More likely for negative outcomes
            elif scenario == 'best_case':
                z -= 0.5  # Less likely for negative outcomes
            
            # Logistic function
            probs = 1 / (1 + np.exp(-z))
            
            # Adjust to target rate
            current_mean = probs.mean()
            shift = target_rate - current_mean
            probs = np.clip(probs + shift, 0.01, 0.99)
            
            # Generate labels
            df[target_name] = (np.random.random(len(df)) < probs).astype(bool)
        
        return df
    
    def _inject_noise(self, df: pd.DataFrame, noise_level: float) -> pd.DataFrame:
        """Inject various types of noise"""
        df = df.copy()
        
        # Missingness
        if noise_level > 0:
            for col in df.select_dtypes(include=[np.number]).columns:
                if not col.endswith('_id'):
                    mask = np.random.random(len(df)) < (noise_level * 0.05)
                    df.loc[mask, col] = np.nan
        
        # Outliers
        if noise_level > 0.3:
            for col in df.select_dtypes(include=[np.number]).columns:
                n_outliers = int(len(df) * noise_level * 0.02)
                if n_outliers > 0:
                    outlier_idx = np.random.choice(len(df), n_outliers, replace=False)
                    mean, std = df[col].mean(), df[col].std()
                    df.loc[outlier_idx, col] = mean + std * np.random.choice([-5, 5], n_outliers)
        
        return df
    
    def _create_splits(self, df: pd.DataFrame, split_config: Dict, schema: Dict) -> pd.DataFrame:
        """Create train/valid/test splits"""
        from sklearn.model_selection import train_test_split
        
        train_size = split_config.get('train', 0.7)
        valid_size = split_config.get('valid', 0.15)
        test_size = split_config.get('test', 0.15)
        
        # Get target column for stratification
        target_col = None
        stratify = None
        
        if 'target_config' in schema:
            target_col = schema['target_config']['name']
            if target_col in df.columns and df[target_col].dtype == bool:
                # Only stratify if we have enough samples of each class
                min_class_count = df[target_col].value_counts().min()
                if min_class_count >= 2 and len(df) >= 30:  # Need at least 2 of each class
                    stratify = df[target_col]
                else:
                    self.assumptions.append("Skipped stratification due to small dataset size")
        
        # Create first split
        train_idx, temp_idx = train_test_split(
            np.arange(len(df)),
            train_size=train_size,
            stratify=stratify,
            random_state=self.seed
        )
        
        # Create second split
        if stratify is not None:
            temp_stratify = df.loc[temp_idx, target_col]
            temp_min_class = temp_stratify.value_counts().min()
            if temp_min_class < 2:
                temp_stratify = None
        else:
            temp_stratify = None
        
        valid_prop = valid_size / (valid_size + test_size)
        valid_idx, test_idx = train_test_split(
            temp_idx,
            train_size=valid_prop,
            stratify=temp_stratify,
            random_state=self.seed
        )
        
        df['split'] = 'train'
        df.loc[valid_idx, 'split'] = 'valid'
        df.loc[test_idx, 'split'] = 'test'
        
        return df
    
    def _validate_and_repair(self, df: pd.DataFrame, schema: Dict) -> pd.DataFrame:
        """Validate data and repair violations"""
        df = df.copy()
        
        for col, spec in schema.items():
            if col == 'target_config' or col not in df.columns:
                continue
            
            # Repair ranges
            if 'min' in spec and pd.api.types.is_numeric_dtype(df[col]):
                violations = (df[col] < spec['min']).sum()
                if violations > 0:
                    self.violations_repaired[f"{col}_min"] = violations
                    df.loc[df[col] < spec['min'], col] = spec['min']
            
            if 'max' in spec and pd.api.types.is_numeric_dtype(df[col]):
                violations = (df[col] > spec['max']).sum()
                if violations > 0:
                    self.violations_repaired[f"{col}_max"] = violations
                    df.loc[df[col] > spec['max'], col] = spec['max']
        
        return df
    
    def _generate_report(self, use_case: str, df: pd.DataFrame, schema: Dict, 
                        scenario: str, noise_level: float):
        """Generate comprehensive report"""
        
        self.report_lines.append(f"Use Case: {use_case}")
        self.report_lines.append(f"Rows Generated: {len(df):,}")
        self.report_lines.append(f"Columns: {len(df.columns)}")
        self.report_lines.append(f"Scenario: {scenario}")
        self.report_lines.append(f"Noise Level: {noise_level:.1%}")
        self.report_lines.append("")
        
        # Target analysis
        if 'target_config' in schema:
            target_name = schema['target_config']['name']
            if target_name in df.columns:
                if df[target_name].dtype == bool:
                    rate = df[target_name].mean()
                    self.report_lines.append(f"Target Variable '{target_name}':")
                    self.report_lines.append(f"  Rate: {rate:.1%}")
                    self.report_lines.append(f"  True: {df[target_name].sum():,}")
                    self.report_lines.append(f"  False: {(~df[target_name]).sum():,}")
                else:
                    self.report_lines.append(f"Target Variable '{target_name}':")
                    self.report_lines.append(f"  Mean: {df[target_name].mean():.2f}")
                    self.report_lines.append(f"  Std: {df[target_name].std():.2f}")
                self.report_lines.append("")
        
        # Split analysis
        if 'split' in df.columns:
            self.report_lines.append("Data Splits:")
            for split in ['train', 'valid', 'test']:
                count = (df['split'] == split).sum()
                pct = count / len(df)
                self.report_lines.append(f"  {split}: {count:,} ({pct:.1%})")
            self.report_lines.append("")
        
        # Data quality
        missing = df.isnull().sum()
        if missing.sum() > 0:
            self.report_lines.append("Missing Values:")
            for col in missing[missing > 0].index:
                self.report_lines.append(f"  {col}: {missing[col]} ({missing[col]/len(df):.1%})")
            self.report_lines.append("")
        
        # Violations repaired
        if self.violations_repaired:
            self.report_lines.append("Constraint Violations Repaired:")
            for constraint, count in self.violations_repaired.items():
                self.report_lines.append(f"  {constraint}: {count}")
            self.report_lines.append("")
        
        # Assumptions
        if self.assumptions:
            self.report_lines.append("Assumptions:")
            for assumption in self.assumptions:
                self.report_lines.append(f"  • {assumption}")


# Example usage function
def quick_generate(use_case: str, rows: int = 1000, scenario: str = 'average_case', 
                  noise: float = 0.0, output: str = None) -> pd.DataFrame:
    """
    Quick generation function for easy use.
    
    Examples:
    ---------
    df = quick_generate("customer churn", rows=5000, scenario='worst_case', noise=0.3)
    df = quick_generate("sales forecasting", rows=10000, output='sales_data.csv')
    df = quick_generate("loan default", rows=2000, scenario='best_case')
    """
    gen = BusinessDataGenerator(seed=42)
    return gen.generate(
        use_case=use_case,
        rows=rows,
        scenario=scenario,
        noise_level=noise,
        train_test_split={'train': 0.7, 'valid': 0.15, 'test': 0.15},
        output_file=output
    )


if __name__ == "__main__":
    print("\n" + "="*70)
    print("AUTONOMOUS BUSINESS DATA GENERATOR")
    print("="*70)
    print("\nReady to generate synthetic data for ANY business use case!")
    print("\nExample usage:")
    print('  df = quick_generate("customer churn", rows=5000, scenario="worst_case")')
    print('  df = quick_generate("sales forecasting", rows=10000, output="sales.csv")')
    print("\nSupported use cases:")
    print("  • Customer churn prediction")
    print("  • Sales forecasting")
    print("  • Loan default modeling")
    print("  • Employee retention")
    print("  • Marketing conversion")
    print("  • E-commerce analytics")
    print("  • Fraud detection")
    print("  • IoT sensor monitoring")
    print("  • And more...")
