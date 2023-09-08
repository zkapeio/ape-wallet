# Ape Wallet contracts
Vyper contracts used in Ape Wallet.

## Overview

Ape Wallet is a smart contract wallet solution supporting social recovery, built on the zkSync Era. Through Ape Wallet, developers can provide a smooth user experience in their products, free of private keys and gas, thereby rapidly attracting massive Web2 users.

Ape Wallet supports paying transaction fees with any token, and will cover all platforms including web, mobile, and browser plug-ins, supporting various invocation methods. Compatible with the latest ERC-4337 account abstraction and ERC-6551 , Nunu Wallet is a leading smart contract wallet solution.


## Testing and Development

### Dependencies

- [python3](https://www.python.org/downloads/release/python-3114/) from version 3.8 to 3.11, python3-dev
- [eth-ape](https://github.com/ApeWorX/ape) - tested with version 0.6.15
- [vyper](https://github.com/vyperlang/vyper) - tested with version 0.3.7
- [ganache-cli](https://github.com/trufflesuite/ganache) - tested with version 7.9.0

Ape wallet contracts are compiled using Vyper, however installation of the required Vyper versions is handled by Ape.

### Setup

To get started, first create and initialize a Python virtual environment. Next, clone the repo and install the developer dependencies:

```
git clone https://github.com/zkapeio/ape-wallet.git
cd ape-wallet
pip install -r requirements.txt
```

### Organization and Workflow

- Creating an account is based on the contract template in the [contracts/factory](./contracts/factory) directory.
- Building transactions, proxy, and guardians are constructed based on the contract templates in the [contracts/manager](./contracts/manager) directory.

### Running the Tests

The test suite contains common tests for all Ape wallet, as well as unique per-manager tests. To run the entire suite:

```
ape test
```

To run tests on a specific manager:

```
ape test tests/<MANAGER NAME>
```

You can optionally include the `--coverage` flag to view a coverage report upon completion of the tests.


## Deployment

To deploy a new ape wallet:
1. Edit the configuration settings within [scripts/main.py](./scripts/main.py).
2. Test the deployment locally against a forked mainnet.
```
ape run deploy --network ethereum:mainnet-fork:hardhat

```
When the script completes it will open a console. You should call the various getter methods on the deployed contracts to ensure the pool has been configured correctly.
3. Deploy the wallet to the mainnet.
```
ape run deploy --network ethereum:mainnet:hardhat
```

## License
(c) Ape Wallet, 2023 - [All rights reserved.](./LICENSE)

