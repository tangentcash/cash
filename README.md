<br/>
<div align="center">
    <br />
    <img src="https://github.com/tangentcash/cash/blob/main/var/images/icon.png?raw=true" alt="Vitex Logo" width="100" />
    <h3>Tangent Protocol / Cash Node</h3>
</div>

## Project information
Tangent Protocol is an software implementation designed as both a library and a validator, essential for maintaining a trustless peer-to-peer network. This network processes, stores, and distributes transactions in the form of a blockchain, offering reliable and fast superchain capabilties.

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
- **Coordinator**: Acts as an asset bridge and must become an attestator, locking the native currency of the blockchain being bridged.
- **Attestator**: Acts as an oracle publishing off-chain transaction into Tangent blockchain.
- **Participant**: Holds a private key share, allowing it to create deposit addresses on other blockchains and sign transactions for withdrawals. Participants are randomly selected into bridges to ensure unpredictability and fairness.

### Security
The asset bridging process employs an N-of-N signature scheme and utilizes [Multi-Party Computation (MPC)](var/documents/TECHNICAL-MPC.md) capabilities to build aggregated signatures or public keys which involves coordinating an array of participants of an asset bridge, ensuring robust security.

### Bridging
Users can deposit native cryptocurrency using any bridging node of their choice. Each node sets its own flat fees for deposits and withdrawals. Users request a deposit address* from a bridging node and send assets to that address. To withdraw assets, users select a bridging node (which can be different from the one used for depositing) and send a withdrawal transaction. The assets will then be sent to the user's selected address.

###### _*EVM blockchains require submitting sender address before depositing._ 

### Consensus
- **Verifiable Delay Function**: Proof of work in form of Wesolowki's verifiable delay function, requiring sequential operations to be computed, unlike classic algorithms that can utilize multithreading.
- **Block Time**: Target block time is 6 seconds, with each block containing at least one transaction. Empty blocks can only be created during the genesis round (first 14,400 blocks).
- **Validator Committee**: Each block is created by a randomly selected committee of up to 12 validators. Validators are ranked by priority within their epoch, preventing lower-priority blocks from replacing higher-priority valid candidate blocks. Lower-priority also requires higher difficulty.
- **Epoch Management**: Epochs cannot be skipped, which may impact availability in favor of security.
- **Rewards and Penalties**: Each accepted block emits 1.25 TAN for the winning validator and applies penalties to validators with higher priority who did not commit their work.

### Network Recovery
In case of a network halt due to the unavailability of the entire committee, any node can create a recovery block that meets the network recovery difficulty, which is 90 times higher than the current difficulty. This ensures a minimum network recovery time of 9 minutes. The recovery block has the lowest priority and can be replaced by a block created by any node selected for the committee in that proposal slot.

## Building
There are several ways to build this project that are explained here:
* [Build locally](var/documents/BUILD-MANUAL.md)
* [Build with Docker](var/documents/BUILD-DOCKER.md)

### Configuration
+ **TAN_BUILD** is a build type (lib, main, test), defaults to "main"
+ **VI_LOGGING** is a logging level (errors, warnings, default, debug, verbose), defaults to "default"

## Dependencies
* [gmp (so)](https://gmplib.org/)
* [libsodium (so)](https://github.com/jedisct1/libsodium)
* [openssl (so)](https://github.com/openssl/openssl)
* [secp256k1 (so)](https://github.com/bitcoin-core/secp256k1)
* [sqlite (so)](https://github.com/sqlite/sqlite)
* [vitex (submodule)](https://github.com/romanpunia/vitex)
* [zlib (so)](https://github.com/madler/zlib)

## License
This project is licensed under the MIT license