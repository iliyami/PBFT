"""
Piazza: https://github.com/cmu-db/benchbase/tree/main/src/main/java/com/oltpbenchmark/benchmarks

SmallBank Benchmark Workload Generator

This module generates SmallBank benchmark workloads with skewed access patterns.
SmallBank simulates a banking application with savings and checking accounts.

Transaction Types:
1. Amalgamate(s, r): Transfer all savings to checking for s, then send payment to r's checking
2. Balance(s): Read checking and savings balances (read-only)
3. DepositChecking(s, amount): Add amount to checking account s
4. SendPayment(s, r, amount): Transfer amount from checking s to checking r
5. TransactSavings(s, amount): Add or subtract amount from savings s (amount can be negative)
6. WriteCheck(s, amount): Deduct amount from checking s (can go negative)
"""

import random
import time
from shared import Shared

class SmallBankWorkloadGenerator:
    """Generate SmallBank benchmark workloads with skewed access patterns"""
    
    def __init__(self, num_accounts=1000, hot_accounts=10, skew_factor=0.8):
        """
        Initialize workload generator
        
        Args:
            num_accounts: Total number of accounts in the system
            hot_accounts: Number of "hot" accounts that receive most requests
            skew_factor: Fraction of requests that go to hot accounts (0.0-1.0)
        """
        self.num_accounts = num_accounts
        self.hot_accounts = hot_accounts
        self.skew_factor = skew_factor
        
        # Transaction type distribution (based on typical SmallBank workloads)
        self.tx_type_weights = {
            'Amalgamate': 0.15,
            'Balance': 0.15,
            'DepositChecking': 0.15,
            'SendPayment': 0.25,
            'TransactSavings': 0.15,
            'WriteCheck': 0.15
        }
        self.tx_types = list(self.tx_type_weights.keys())
        self.tx_weights = list(self.tx_type_weights.values())
    
    def get_account(self):
        """Get account ID with skewed distribution (Zipf-like)"""
        if random.random() < self.skew_factor:
            # Hot account
            return random.randint(1, min(self.hot_accounts, self.num_accounts))
        else:
            # Cold account
            return random.randint(1, self.num_accounts)
    
    def generate_transaction(self, sequence_number=None):
        """
        Generate a random SmallBank transaction
        
        Args:
            sequence_number: Optional sequence number (if None, will be assigned later)
            
        Returns:
            tuple: (sequence_number, (tx_type, args)) format compatible with PBFT
        """
        # Select transaction type based on weights
        tx_type = random.choices(self.tx_types, weights=self.tx_weights)[0]
        
        # Generate transaction based on type
        if tx_type == 'Amalgamate':
            s = self.get_account()
            r = self.get_account()
            args = (s, r)
            
        elif tx_type == 'Balance':
            s = self.get_account()
            args = (s,)
            
        elif tx_type == 'DepositChecking':
            s = self.get_account()
            amount = random.randint(1, 100)
            args = (s, amount)
            
        elif tx_type == 'SendPayment':
            s = self.get_account()
            r = self.get_account()
            amount = random.randint(1, 50)
            args = (s, r, amount)
            
        elif tx_type == 'TransactSavings':
            s = self.get_account()
            amount = random.randint(-50, 100)
            args = (s, amount)
            
        elif tx_type == 'WriteCheck':
            s = self.get_account()
            amount = random.randint(1, 50)
            args = (s, amount)
        
        # Format: (tx_type, args) - this will be stored as (seq_num, (tx_type, args))
        transaction = (tx_type, args)
        
        if sequence_number is not None:
            return (sequence_number, transaction)
        return transaction
    
    def generate_workload(self, num_transactions, start_seq=1):
        """
        Generate a complete workload
        
        Args:
            num_transactions: Number of transactions to generate
            start_seq: Starting sequence number
            
        Returns:
            list: List of transactions in format [(seq_num, (tx_type, args)), ...]
        """
        transactions = []
        for i in range(num_transactions):
            seq_num = start_seq + i
            tx = self.generate_transaction(seq_num)
            transactions.append(tx)
        return transactions
    
    def save_to_csv(self, transactions, filename):
        """
        Save workload to CSV file compatible with test input format
        
        Args:
            transactions: List of transactions
            filename: Output CSV filename
        """
        with open(filename, 'w') as f:
            f.write("Set Number,Transactions,Live Servers,Byzantine Servers,Attack\n")
            f.write("1,\"")
            
            tx_strings = []
            for seq_num, (tx_type, args) in transactions:
                if tx_type == 'Amalgamate':
                    s, r = args
                    # Convert to alphabet format
                    s_letter = Shared.get_alphabet_for_number(s) if s <= 10 else str(s)
                    r_letter = Shared.get_alphabet_for_number(r) if r <= 10 else str(r)
                    tx_strings.append(f"({tx_type}({s_letter},{r_letter}))")
                elif tx_type == 'Balance':
                    s = args[0]
                    s_letter = Shared.get_number_for_alphabet(s) if isinstance(s, str) else s
                    s_letter = Shared.get_alphabet_for_number(s_letter) if s_letter and s_letter <= 10 else str(s_letter)
                    tx_strings.append(f"({tx_type}({s_letter}))")
                elif tx_type in ['DepositChecking', 'TransactSavings', 'WriteCheck']:
                    s, amount = args
                    s_letter = Shared.get_alphabet_for_number(s) if s <= 10 else str(s)
                    tx_strings.append(f"({tx_type}({s_letter},{amount}))")
                elif tx_type == 'SendPayment':
                    s, r, amount = args
                    s_letter = Shared.get_alphabet_for_number(s) if s <= 10 else str(s)
                    r_letter = Shared.get_alphabet_for_number(r) if r <= 10 else str(r)
                    tx_strings.append(f"({tx_type}({s_letter},{r_letter},{amount}))")
            
            f.write(",".join(tx_strings))
            f.write("\",\"[n1, n2, n3, n4, n5, n6, n7]\",[],[]\n")


def create_smallbank_benchmark(num_transactions=1000, num_accounts=1000, hot_accounts=10, 
                                skew_factor=0.8, output_file="tests/smallbank_benchmark.csv"):
    """
    Create a SmallBank benchmark workload file
    
    Args:
        num_transactions: Number of transactions to generate
        num_accounts: Total number of accounts
        hot_accounts: Number of hot accounts
        skew_factor: Skew factor (0.0-1.0)
        output_file: Output CSV file path
    """
    generator = SmallBankWorkloadGenerator(
        num_accounts=num_accounts,
        hot_accounts=hot_accounts,
        skew_factor=skew_factor
    )
    
    transactions = generator.generate_workload(num_transactions)
    generator.save_to_csv(transactions, output_file)
    print(f"Generated SmallBank benchmark with {num_transactions} transactions")
    print(f"Saved to {output_file}")
    print(f"Hot accounts: {hot_accounts}, Skew factor: {skew_factor}")


if __name__ == "__main__":
    # Example: Generate a benchmark workload
    create_smallbank_benchmark(
        num_transactions=100,
        num_accounts=100,
        hot_accounts=10,
        skew_factor=0.8,
        output_file="tests/smallbank_test.csv"
    )

