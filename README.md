# ERC 1056 - Upgraded Ethereum DID registry from Uport

https://github.com/uport-project/ethr-did-registry

## ChangeLOG

Moved contracts to solidity 0.5.
Fixed migrations.
Fixed the test suite to be web3 1.0 compliant.

Needs ganache running at http://localhost:8545

```
truffle compile

truffle migrate --reset

truffle test
```

### FOR running against Kaleido

```
export PRIVATE_KEY=<Your Pvt Key>
export NODE_ADDRESS=<Your Kaleido Node Address>
```

### Then run the signing tests

```
truffle test test/kaleido_test.js --network imda
```
