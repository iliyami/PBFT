# Linear PBFT Consensus Protocol for Distributed Banking Application

## Project Overview

This project implements a linear version of the PBFT consensus protocol for a distributed banking application. The system consists of 7 servers and 10 clients, where the primary server is responsible for processing transactions initiated by each client.

## Features

- Linaer PBFT consensus protocol implementation
- Distributed transaction processing
- Fault tolerance for up to F=2 Byzantine nodes
- Local transaction logging and global datastore using Sqlite

## Requirements

- Python 3.7+ (or your chosen programming language)
- Network socket library (built-in)

## Setup

1. Clone the repository:


2. Install dependencies:

pip install -r requirements.txt

## Usage

1. Start the servers:

python main.py

2. The program will read from an input CSV file containing sets of transactions.

3. Follow the prompts to process each set of transactions.

4. Use the following commands between transaction sets:
- `1.<server_id>`: Print the local log of a given server
- `2.<server_id>`: Print the status of a given server
- `3.<server_id>`: Print the datastore of a given server
- `4`            : Print all "New View" messages
- `5.<server_id>`: Print throughput and latency metrics of a given server

## Fix known setup issues
1. Server failed to run due to used address

        sudo lsof -t -i:<port_num>

## Performance

The implementation aims to demonstrate reasonable performance in terms of throughput (transactions committed per second) and latency (average processing time per transaction).

## Bonus Features (Optional)

- [ ] Checkpointing mechanism
- [X] Threshold Signature
- [X] Optimistic phase reduction

## Contributors

- [Iliya Mirzaei]

## License

This project is part of the CSE 535: Distributed Systems course and is subject to the course's academic policies.