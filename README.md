<br/>
<div align="center">
    <br />
    <img src="https://github.com/tangentcash/cash/blob/main/var/images/favicon.png?raw=true" alt="Tangent Protocol Logo" width="100" />
    <h3>Tangent Protocol / Cash Node</h3>
</div>

## Project information
Tangent Protocol is an software implementation designed as a validator node, essential for maintaining a trustless peer-to-peer network. This network processes, stores, and distributes transactions in the form of a blockchain, offering reliable and fast superchain capabilties.

### Asset Bridging
Tangent's primary utility lies in its asset bridging capabilities, allowing users to deposit and withdraw (lock and unlock) cryptocurrencies into the Tangent network. This feature significantly enhances the speed and efficiency of unbounded DeFi operations.

### Performance
- **Transaction Speed**: Optimized for moderately fast transaction processing, supporting up to 210 transactions per second (TPS) with instant finality*.
- **Fees**: Implements market-based transaction fees to reduce the operational costs of node software.
- **Blockchain Support**: Transactions can be conducted using cryptocurrencies or tokens from other blockchains, as well as Tangent's native cryptocurrency.

###### _*Instant finality when block has best priority._ 

### Interoperability
Tangent Protocol supports interoperability with other blockchains, focusing on essential functions such as blockchain scanning, cryptographic operations, transaction broadcasts. This streamlined approach allows Tangent to support various transaction types and smart contracts without the need for additional bridging complexity.

### Node operations
Nodes download and validate data from seeder nodes, gradually forming a list of neighboring nodes. They can also publish new network data, including transactions and blocks.

- **Producer**: Acts as block producer that can create, solve and broadcast blocks to network of nodes.
- **Attester**: Acts as an asset bridge and an oracle publishing off-chain transaction into Tangent blockchain.
- **Participant**: Holds a private key share, allowing it to create deposit addresses on other blockchains and sign transactions for withdrawals. Participants are randomly selected into bridges to ensure unpredictability and fairness.

### Security
The asset bridging process employs an N-of-N signature scheme and utilizes [Multi-Party Computation (MPC)](var/documents/TECHNICAL-MPC.md) capabilities to build aggregated signatures or public keys which involves coordinating an array of participants of an asset bridge, ensuring robust security.

### Bridging
Users can deposit native cryptocurrency using any bridging node of their choice. Each node sets its own flat fees for deposits and withdrawals. Users request a deposit address* from a bridging node and send assets to that address. To withdraw assets, users select a bridging node (which can be different from the one used for depositing) and send a withdrawal transaction. The assets will then be sent to the user's selected address.

###### _*EVM blockchains require submitting sender address before depositing._ 

### Consensus
- **Verifiable Delay Function**: Proof of work in form of Wesolowki's verifiable delay function, requiring sequential operations to be computed, unlike classic algorithms that can utilize multithreading.
- **Block Time**: Target block time is 12 seconds. Genesis round (first 7,200 blocks) will produce 75x rewards to ensure network security at initial stage.
- **Validator Committee**: Each block is created by a randomly selected committee of up to 12 validators. Validators are ranked by priority within their epoch, preventing lower-priority blocks from replacing higher-priority valid candidate blocks. Lower-priority also requires higher difficulty.
- **Epoch Management**: Epochs cannot be skipped, which may impact availability in favor of security.
- **Rewards and Penalties**: Each accepted block emits 1.2 TAN for the winning validator and applies penalties to validators with higher priority who did not commit their work.

### Network Recovery
In case of a network halt due to the unavailability of the entire committee, any node can create a recovery block that meets the network recovery difficulty, which is 90 times higher than the current difficulty. This ensures a minimum network recovery time of 9 minutes. The recovery block has the lowest priority and can be replaced by a block created by any node selected for the committee in that proposal slot.

## Building
There are several ways to build this project that are explained here:
* [Build locally](var/documents/BUILD-MANUAL.md)
* [Build with Docker](var/documents/BUILD-DOCKER.md)

### Configuration
+ **TAN_TEST** builds a test target with multiple cases covered
+ **VI_LOGGING** is a logging level (errors, warnings, default, debug, verbose), defaults to "default"

## Dependencies
* [gmp (so)](https://gmplib.org/)
* [libsodium (so)](https://github.com/jedisct1/libsodium)
* [openssl (so)](https://github.com/openssl/openssl)
* [secp256k1 (so)](https://github.com/bitcoin-core/secp256k1)
* [sqlite (so)](https://github.com/sqlite/sqlite)
* [vitex (submodule)](https://github.com/romanpunia/vitex)
* [zlib (so)](https://github.com/madler/zlib)

## Links

[![Project website](https://img.shields.io/badge/Tangent-Cash-3d665c.svg?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB2ZXJzaW9uPSIxLjEiIHdpZHRoPSI2NDBweCIgaGVpZ2h0PSI2NDBweCIgc3R5bGU9InNoYXBlLXJlbmRlcmluZzpnZW9tZXRyaWNQcmVjaXNpb247IHRleHQtcmVuZGVyaW5nOmdlb21ldHJpY1ByZWNpc2lvbjsgaW1hZ2UtcmVuZGVyaW5nOm9wdGltaXplUXVhbGl0eTsgZmlsbC1ydWxlOmV2ZW5vZGQ7IGNsaXAtcnVsZTpldmVub2RkIj4gDQogICAgPHJlY3QgZmlsbD0iIzNkNjY1YyIgeD0iMCIgeT0iMCIgd2lkdGg9IjY0MCIgaGVpZ2h0PSI2NDAiIHJ4PSIxNjAiIHJ5PSIxNjAiLz4NCiAgICA8cGF0aCBmaWxsPSIjNDhmZmIwIiBkPSJNIDMwNS41LDEzOS41IEMgMzA4LjI2NSwxMzkuNzk4IDMxMC43NjUsMTQwLjc5OCAzMTMsMTQyLjVDIDMyMC44MzksMTUyLjg1MyAzMjguMTcyLDE2My41MiAzMzUsMTc0LjVDIDM0Ny45MTQsMTk1LjMyNSAzNjAuNTgxLDIxNi4zMjUgMzczLDIzNy41QyA0MDguNDI2LDI5Mi41ODcgNDQzLjQyNiwzNDcuOTIgNDc4LDQwMy41QyA0ODQuMzAyLDQxNC4xMjEgNDkwLjEzNiw0MjQuOTU1IDQ5NS41LDQzNkMgNDk0LjA4NCw0MzguODM1IDQ5Mi40MTcsNDQxLjUwMiA0OTAuNSw0NDRDIDM3Ni44MzQsNDQ0LjUgMjYzLjE2Nyw0NDQuNjY3IDE0OS41LDQ0NC41QyAxNDcuODE5LDQ0MS43OTcgMTQ2LjE1Myw0MzkuMTMxIDE0NC41LDQzNi41QyAxNDcuNjMzLDQyOC41MTkgMTUxLjQ2Nyw0MjAuODUyIDE1Niw0MTMuNUMgMTc4Ljc0OCwzNzcuNjczIDIwMS4yNDgsMzQxLjY3MyAyMjMuNSwzMDUuNUMgMjM1Ljk2OSwyODUuMjQ4IDI0OC45NjksMjY1LjI0OCAyNjIuNSwyNDUuNUMgMjY0LjE0NSwyNDQuMzA0IDI2NS44MTEsMjQzLjMwNCAyNjcuNSwyNDIuNUMgMjczLjE3OSwyNDMuMzM5IDI3Ny4zNDYsMjQ2LjMzOSAyODAsMjUxLjVDIDI5Ny4wMjUsMjc3Ljg0OSAzMTMuMTkyLDMwNC42ODIgMzI4LjUsMzMyQyAzMjMuNTk1LDM0MC44OTkgMzE2LjI2MiwzNDYuODk5IDMwNi41LDM1MEMgMzAzLjUxOCwzNTAuNDk4IDMwMC41MTgsMzUwLjY2NSAyOTcuNSwzNTAuNUMgMjk2LjMxMiwzNDkuNjM2IDI5NS4xNDUsMzQ4LjYzNiAyOTQsMzQ3LjVDIDI4Ni4zMDQsMzM0Ljk5MyAyNzguNDcsMzIyLjY2IDI3MC41LDMxMC41QyAyNjkuMTkyLDMwNi41OTcgMjY3LjY5MiwzMDYuNTk3IDI2NiwzMTAuNUMgMjQ5LjA2MiwzMzguNDMzIDIzMS43MjksMzY2LjA5OSAyMTQsMzkzLjVDIDIxMS4yNzQsMzk3LjYxOSAyMDkuMTA3LDQwMS45NTIgMjA3LjUsNDA2LjVDIDIxNy4wNDMsNDA2LjYyOSAyMjYuMzc3LDQwNi42MjkgMjM1LjUsNDA2LjVDIDI4OS4yNjQsNDA3LjgzIDM0Mi45MzEsNDA3LjgzIDM5Ni41LDQwNi41QyA0MDguNSw0MDYuNSA0MjAuNSw0MDYuNSA0MzIuNSw0MDYuNUMgNDMyLjY0OSw0MDUuNDQ4IDQzMi40ODMsNDA0LjQ0OCA0MzIsNDAzLjVDIDM4NC42NDMsMzI5LjQ0OCAzMzguMzA5LDI1NC43ODEgMjkzLDE3OS41QyAyOTAuNTksMTc0LjY4NiAyODguNzU3LDE2OS42ODYgMjg3LjUsMTY0LjVDIDI4OS45OTMsMTU4LjIyMSAyOTMuMTYsMTUyLjIyMSAyOTcsMTQ2LjVDIDI5OS42MjgsMTQzLjc5IDMwMi40NjEsMTQxLjQ1NiAzMDUuNSwxMzkuNSBaIi8+DQo8L3N2Zz4=)](https://tangent.cash/)
[![Discord server](https://img.shields.io/badge/Discord-Server-5865f2?logo=discord)](https://discord.gg/TyubmucCTB)



## License

This project is licensed under the MIT license


































