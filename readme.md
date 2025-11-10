# Linear PBFT Banking System with Byzantine Fault Tolerance

A distributed banking application implementing the Linear Practical Byzantine Fault Tolerance (PBFT) consensus protocol for state machine replication, with comprehensive support for Byzantine failures and performance optimizations.

## Overview

This project implements a fault-tolerant distributed banking system using the Linear PBFT consensus algorithm. The system ensures that all banking transactions are consistently maintained across multiple nodes (replicas) through consensus-based state machine replication, even in the presence of Byzantine (malicious) failures.

## Features

- **Linear PBFT Consensus Protocol**: Implements leader-based consensus with linear communication complexity
- **Distributed Banking**: Supports 10 clients (A-J) with transfer and balance transactions
- **Byzantine Fault Tolerance**: Handles up to F=2 malicious nodes (out of 7 total nodes)
- **View Change Mechanism**: Automatic leader replacement when failures are detected
- **Read-Only Transactions**: Balance queries that bypass consensus for improved performance
- **Checkpointing (Bonus 1)**: Periodic state saving for efficient recovery and log optimization
- **Threshold Signatures (Bonus 2)**: Constant-size messages using threshold signature scheme
- **Optimistic Phase Reduction (Bonus 3)**: Fast path optimization when all replicas are non-faulty
- **SmallBank Benchmark (Bonus 4)**: Comprehensive performance evaluation with industry-standard benchmark

## System Architecture

- **7 PBFT Nodes**: Distributed across ports 5001-5007 (3f+1 where f=2)
- **10 Banking Clients**: Clients A through J with initial balance of 10 units each
- **Leader-based Consensus**: Single leader coordinates all transactions
- **Majority-based Decisions**: Requires 2f+1 (5 out of 7) nodes for consensus
- **Linear Communication**: O(n) message complexity instead of O(n²)

## Key Components

### Core PBFT Implementation (`main.py`)
- **Normal Case Operation**: Pre-prepare, prepare, and commit phases with linear communication
- **View Change Routine**: Automatic leader election when current leader is suspected faulty
- **Byzantine Failure Handling**: Supports 5 types of malicious behaviors
- **State Synchronization**: Catch-up mechanisms for failed nodes using checkpoints
- **Checkpointing system** for efficient state recovery
- **Threshold signatures** for constant-size commit messages
- **Optimistic phase reduction** for fast-path execution

### Client Implementation (`client.py`)
- Transaction request handling with retry logic
- Read-only balance requests with 2f+1 reply collection
- View tracking and leader discovery
- Closed-loop client behavior (wait for response before next request)

### Byzantine Failure Types
1. **Invalid Signature**: Malicious nodes send improperly signed messages
2. **Crash**: Leader fails to send prepare/commit messages or new-view messages
3. **In-Dark**: Malicious nodes avoid sending messages to specific honest nodes
4. **Timing**: Malicious leader delays messages to cause timeouts
5. **Equivocation**: Malicious leader sends conflicting pre-prepare messages with different sequence numbers

## PBFT Protocol Phases

### Normal Case Operation (Linear PBFT)
1. **Pre-Prepare**: Leader assigns sequence number and multicasts to all backups
2. **Prepare**: Backups send prepare messages to leader (collector)
3. **Prepare-Ack**: Leader collects 2f+1 prepare messages and broadcasts combined message
4. **Commit**: Replicas send commit messages to leader
5. **Commit-Ack**: Leader collects 2f+1 commit messages and broadcasts combined message
6. **Execute**: Transaction is executed and reply sent to client

### View Change
- Triggered by timeout when leader is suspected faulty
- Backups exchange view-change messages with prepared requests
- New leader (v+1 mod n) creates new-view message with 'O' field
- System transitions to new view and processes pending transactions

## Usage

### Run Basic Tests
```bash
python3 main.py --test tests/input1.csv
```

### Run with Debug Output
```bash
python3 main.py --test tests/input1.csv --debug
```

### Run Non-Interactive Mode
```bash
python3 main.py --test tests/input1.csv --non-interactive
```

### Generate SmallBank Benchmark Workload
```bash
python3 smallbank_workload.py
```

### Run with SmallBank Transactions
```bash
python3 main.py --test tests/smallbank_test.csv
```

The system is fully backward compatible - you can run with existing test files:
```bash
python3 main.py --test tests/input1.csv
```

### Interactive Commands
During execution, use the following commands:
- `1.<server_id>`: Print the local log of a given server
- `2.<server_id>`: Print the status of a transaction on a given server
- `3.<server_id>`: Print the datastore (balances) of a given server
- `4`: Print all "New View" messages
- `5.<server_id>`: Print throughput and latency metrics of a given server

## Test Scenarios

The system handles various scenarios including:
- Normal transaction processing
- Leader failures and view changes
- Byzantine attacks (invalid signature, crash, in-dark, timing, equivocation)
- Node isolation and recovery
- Concurrent view changes
- Insufficient nodes for consensus
- State synchronization after failures
- Read-only balance queries
- Equivocation attack resolution with no-op operations

## Files

- `main.py` - Core Linear PBFT implementation
- `client.py` - Client implementation with transaction and balance request handling
- `shared.py` - Shared utilities and constants
- `smallbank_workload.py` - SmallBank benchmark workload generator (Bonus 4)
- `tests/` - Comprehensive test suite with various scenarios

## Bonus Implementations

### Bonus 1: Checkpointing
- **Periodic state saving** after every 10 committed requests (configurable)
- **Efficient recovery** using checkpoints instead of processing all previous requests
- **Log optimization** with checkpoint-based catch-up mechanisms
- **State synchronization** for failed nodes using checkpoint data
- **Checkpoint certificates** included in view-change messages

### Bonus 2: Threshold Signatures
- **Constant message size** using threshold signature scheme (2f+1 out of 3f+1)
- **Reduced communication overhead** by combining multiple signatures into one
- **Signature collection** by leader (collector) and broadcast to all replicas
- **Verification** of threshold signatures for commit messages

### Bonus 3: Optimistic Phase Reduction
- **Fast path execution** when all 3f+1 replicas are non-faulty
- **Eliminates commit phase** by collecting all prepare messages
- **Combined signature** from all replicas in prepare phase
- **Fallback to slow path** if not all replicas respond in time

### Bonus 4: SmallBank Benchmark
- **Comprehensive performance evaluation** using industry-standard SmallBank benchmark
- **Realistic banking workloads** with 6 transaction types and skewed access patterns
- **Workload generator** with configurable parameters (account count, hot accounts, skew factor)
- **Backward compatible** with existing legacy transfer transactions
- **Transaction types**: Amalgamate, Balance, DepositChecking, SendPayment, TransactSavings, WriteCheck

## Performance Characteristics

- **Fault Tolerance**: Handles up to F=2 Byzantine failures out of 7 nodes
- **Communication Complexity**: Linear O(n) instead of quadratic O(n²)
- **Consensus Latency**: 3 phases (pre-prepare, prepare, commit) in normal case
- **View Change**: Automatic recovery from leader failures
- **Throughput**: Optimized for high transaction rates with linear communication

## Academic Context

This project implements the Linear PBFT consensus protocol as described in the course materials, following the original PBFT paper. At the end I have used AI assistance for creating this readme and understanding the benchmark behavior and context.
