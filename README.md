# Bitcoin-Stacks Atomic Bridge Smart Contract

A production-grade implementation of a non-custodial, bidirectional bridge between Bitcoin and Stacks blockchains, enabling secure cross-chain asset transfers with Bitcoin-native security guarantees.

## Overview

The Bitcoin-Stacks Atomic Bridge facilitates trustless cross-chain transactions through a combination of SPV proofs, multi-sig validator consensus, and cryptographic verification mechanisms. The system implements a novel approach to cross-chain interoperability while maintaining compliance with Bitcoin's security model and Stacks' smart contract capabilities.

### Key Features

- **Bi-directional Asset Transfers**: Support for BTC ↔ xBTC and STX ↔ wSTX conversions
- **Validator Quorum System**: Dynamic validator set with voting power weighting
- **SPV Proof Verification**: Bitcoin transaction validation without full node dependency
- **Emergency Circuit Breaker**: Deployer-controlled pause functionality
- **BIP-322 Signature Compliance**: Secure Bitcoin address verification
- **FAT-2 Token Standard**: Compatible with Stacks token ecosystem
- **Multi-hop Support**: Prepares for Lightning Network integration

## Technical Specifications

| Category             | Details                                                               |
| -------------------- | --------------------------------------------------------------------- |
| Language             | Clarity 2.1                                                           |
| Compatibility        | Stacks 2.1+, Bitcoin Core 24.0+                                       |
| Signature Standard   | BIP-340 Schnorr / BIP-322 Message Signing                             |
| Compliance Standards | FAT-2, BIP300 (Drivechain concepts), SIP-009 (NFT Standard)           |
| Security Model       | Bitcoin finality (6 confirmations) + Validator quorum (5/8 multi-sig) |

## Core Components

### 1. Bridge State Management

- Operational status toggle (active/paused)
- Total bridged value tracking
- Bitcoin block height synchronization

### 2. Cross-chain Transaction Tracking

```clarity
(define-map deposits
  { btc-txid: (buff 32) }
  {
    amount: uint,
    recipient: principal,
    status: (enum 'pending 'confirmed 'redeemed),
    confirmations: uint,
    locktime: uint,
    btc-sender: (buff 33)
  }
)
```

### 3. Validator Governance

- Dynamic validator set management
- Voting power allocation
- Signature weight accumulation

### 4. Withdrawal Management

```clarity
(define-map withdrawals
  { nonce: uint }
  {
    amount: uint,
    btc-recipient: (buff 34),
    stx-sender: principal,
    burn-proof: (buff 64),
    status: (enum 'pending 'processed)
  }
)
```

## Workflows

### Bitcoin → Stacks Transfer Flow

1. **BTC Locking**: User initiates BTC transfer to bridge address
2. **SPV Proof Submission**: Submit Merkle proof via `lock-btc` function
3. **Validator Confirmation**: Validators verify and sign with Schnorr signatures
4. **Token Minting**: xBTC minted after quorum confirmation

### Stacks → Bitcoin Transfer Flow

1. **xBTC Burning**: User invokes `burn-xbtc` with BTC recipient address
2. **Withdrawal Request**: Creates pending withdrawal entry
3. **Validator Processing**: Validators batch process withdrawal requests
4. **BTC Release**: Signed transaction broadcast to Bitcoin network

## Security Model

### Multi-layer Protection

1. **Validator Quorum**: 5/8 multi-sig requirement for asset releases
2. **SPV Proofs**: SHA-256d Merkle proof verification for Bitcoin transactions
3. **Circuit Breaker**: Emergency pause functionality (deployer controlled)
4. **Time Locks**: Bitcoin HTLC-style refund capabilities
5. **Audit Trails**: Immutable transaction logging on both chains

```clarity
(define-public (confirm-deposit
    (btc-txid (buff 32))
    (signature (buff 65))
  (let (
    (validator-power (get voting-power (map-get? validators tx-sender)))
    (asserts! (> validator-power u0) (err ERR_UNAUTHORIZED))
    (asserts! (verify-btc-sig btc-txid signature) (err ERR_SIG_VALIDATION))
  )
)
```

### Example Usage

**Initiate Bitcoin Deposit:**

```clarity
(lock-btc 0x1234... 500000 'STXADDRESS
  0xmerkleproof 0xbc1q...)
```

**Burn xBTC for Withdrawal:**

```clarity
(burn-xbtc u500000 0xbc1q... 0x6d656d6f)
```

## Compliance Features

| Standard               | Implementation Details                    |
| ---------------------- | ----------------------------------------- |
| FAT-2 (Fungible Token) | xBTC mint/burn compliance                 |
| BIP-300 (Drivechains)  | SPV proof handling for Bitcoin sidechain  |
| BIP-322 (Signatures)   | Message signing for Bitcoin address proof |
| SIP-009 (NFTs)         | Future NFT bridge compatibility layer     |

## Contributing

1. Fork repository
2. Create feature branch (`git checkout -b feature/improvement`)
3. Commit changes (`git commit -am 'Add new feature'`)
4. Push branch (`git push origin feature/improvement`)
5. Open Pull Request
