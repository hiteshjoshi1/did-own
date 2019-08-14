var ethutil = require("ethereumjs-util");
var sha3 = require("js-sha3").keccak_256;
var EthereumDIDRegistry = artifacts.require("./EthereumDIDRegistry.sol");
var BN = require("bn.js");
var ethers = require("ethers");

contract("EthereumDIDRegistry", function(accounts) {
  let didReg;
  const privateKey = Buffer.from(
    "a285ab66393c5fdda46d6fbad9e27fafd438254ab72ad5acb681a0e9f20f5d7b",
    "hex"
  );
  const signerAddress = "0x2036c6cd85692f0fb2c26e6c6b2eced9e4478dfd";

  const privateKey2 = Buffer.from(
    "a285ab66393c5fdda46d6fbad9e27fafd438254ab72ad5acb681a0e9f20f5d7a",
    "hex"
  );
  const signerAddress2 = "0xea91e58e9fa466786726f0a947e8583c7c5b3185";

  const privateKey3 = Buffer.from(
    "E9E9046F6ED1CB8E615C200B0A1D6796C4B40795382517601B19937BF58D23F4",
    "hex"
  );

  const signerAddress3 = "0xDE4dB6938e4e54717FeCC48025Cc718bA28A4C99";

  const identity = signerAddress2;
  let owner;
  let previousChange;

  const hex = web3.utils.asciiToHex("attestor");
  const hextoBytes32 = web3.utils.hexToBytes(hex);

  const someKey = "D/E Card IMM27";

  const someValue = "Hitesh";

  const someKeyHex = web3.utils.asciiToHex(someKey);
  const someKeyBytes = web3.utils.hexToBytes(someKeyHex);

  const valueHex = web3.utils.asciiToHex(someValue);
  //   let valueHexEther = ethers.utils.hexlify(ethers.utils.toUtf8Bytes(someValue));
  const valueInBytes = web3.utils.hexToBytes(valueHex);

  //   let someKeyEtherBytes = ethers.utils.formatBytes32String(someKey);

  //   let etherBytes = ethers.utils.toUtf8Bytes(someValue);

  before(async () => {
    didReg = await EthereumDIDRegistry.deployed();
  });
  function getBlock(blockNumber) {
    return new Promise((resolve, reject) => {
      web3.eth.getBlock(blockNumber, (error, block) => {
        if (error) return reject(error);
        resolve(block);
      });
    });
  }

  function getLogs(filter) {
    return new Promise((resolve, reject) => {
      filter.get((error, events) => {
        if (error) return reject(error);
        resolve(events);
      });
    });
  }

  function stripHexPrefix(str) {
    if (str.startsWith("0x")) {
      return str.slice(2);
    }
    return str;
  }

  function bytes32ToString(bytes) {
    return Buffer.from(bytes.slice(2).split("00")[0], "hex").toString();
  }

  function stringToBytes32(str) {
    const buffstr = Buffer.from(str).toString("hex");
    return buffstr + "0".repeat(64 - buffstr.length);
  }

  function leftPad(data, size = 64) {
    if (data.length === size) return data;
    return "0".repeat(size - data.length) + data;
  }

  async function signData(identity, signer, key, data) {
    // get the contract nonce - not the Blockchain nonce, replay attack prevention
    const nonce = await didReg.nonce(signer);
    const paddedNonce = leftPad(Buffer.from([nonce], 64).toString("hex"));
    const dataToSign =
      "1900" +
      stripHexPrefix(didReg.address) +
      paddedNonce +
      stripHexPrefix(identity) +
      data;
    const hash = Buffer.from(sha3.buffer(Buffer.from(dataToSign, "hex")));
    const signature = ethutil.ecsign(hash, key);
    const publicKey = ethutil.ecrecover(
      hash,
      signature.v,
      signature.r,
      signature.s
    );
    return {
      r: "0x" + signature.r.toString("hex"),
      s: "0x" + signature.s.toString("hex"),
      v: signature.v
    };
  }

  describe("identityOwner()", () => {
    describe("default owner", () => {
      it("should return the identity address itself", async () => {
        const owner = await didReg.identityOwner(signerAddress);
        assert.equal(owner.toUpperCase(), signerAddress.toUpperCase());
      });
    });

    describe("using signature", () => {
      describe("as current owner", () => {
        let tx;
        before(async () => {
          previousChange = await didReg.changed(signerAddress2); // where previous block change is
          const curOwner = await didReg.identityOwner(signerAddress2); // who is the currennt owner
          assert.equal(signerAddress2.toUpperCase(), curOwner.toUpperCase()); // so the address itself is owner by default
          const sig = await signData(
            signerAddress2, // is the identity did address
            signerAddress2, // who is signing and current owner
            privateKey2, // signing addres pvt key
            Buffer.from("setAttribute").toString("hex") + // which method to call
            stringToBytes32(someKey) + //the attribute Name
            Buffer.from(someValue).toString("hex") + // the attribute value
              leftPad(new BN(86400).toString(16)) // the attribute validity
          );
          console.log(signerAddress2);
          console.log(sig.v);
          console.log(sig.r);
          console.log(sig.s);
          console.log(someKey);
          console.log(someValue);

          tx = await didReg.setAttributeSigned(
            signerAddress2,
            sig.v,
            sig.r,
            sig.s,
            someKeyHex,
            valueHex,
            86400,
            { from: signerAddress }
          );
          console.log(tx);
          block = await getBlock(tx.receipt.blockNumber);
        });

        it("should sets changed to transaction block", async () => {
          const latest = await didReg.changed(signerAddress2);
          const latestBN = web3.utils.toBN(latest).toString();
          assert.equal(latestBN, tx.receipt.blockNumber);
        });
        it("should create DIDAttributeChanged event", () => {
          const event = tx.logs[0];
          assert.equal(event.event, "DIDAttributeChanged");

          assert.equal(
            event.args.identity.toUpperCase(),
            signerAddress2.toUpperCase()
          );
          assert.equal(bytes32ToString(event.args.name), someKey);
          assert.equal(event.args.value, valueHex);
          assert.equal(event.args.validTo.toNumber(), block.timestamp + 86400);
          assert.equal(
            event.args.previousChange.toNumber(),
            previousChange.toNumber()
          );
        });
      });
    });
  });

  describe("changeOwner()", () => {
    describe("using signature", () => {
      describe("as current owner", () => {
        let tx;
        before(async () => {
          const sig = await signData(
            signerAddress2,
            signerAddress2,
            privateKey2,
            Buffer.from("changeOwner").toString("hex") +
              stripHexPrefix(signerAddress3)
          );
          tx = await didReg.changeOwnerSigned(
            signerAddress2,
            sig.v,
            sig.r,
            sig.s,
            signerAddress3,
            { from: signerAddress }
          );
        });
        it("should change owner mapping", async () => {
          const owner2 = await didReg.owners(signerAddress2);
          assert.equal(owner2.toLowerCase(), signerAddress3.toLowerCase());
        });
        it("should sets changed to transaction block", async () => {
          const latest = await didReg.changed(signerAddress2);
          assert.equal(latest, tx.receipt.blockNumber);
        });
        // it("should create DIDOwnerChanged event", () => {
        //   const event = tx.logs[0];
        //   // console.log(event.args)
        //   assert.equal(event.event, "DIDOwnerChanged");
        //   console.log(event.args.identity.toLowerCase());
        //   assert.equal(
        //     event.args.identity.toLowerCase(),
        //     signerAddress2.toLowerCase()
        //   );
        //   assert.equal(
        //     event.args.owner.toLowerCase(),
        //     signerAddress3.toLowerCase()
        //   );
        //   assert.equal(event.args.previousChange.toNumber(), 248912);
        // });
      });
    });
  });

  //   describe("addDelegate()", () => {
  //     describe("using signature", () => {
  //       describe("as current owner", () => {
  //         let tx1;
  //         let block1;
  //         let previousChange1;
  //         let tx2;
  //         let block2;
  //         let previousChange2;

  //         before(async () => {
  //           previousChange1 = await didReg.changed(signerAddress2);
  //           let sig = await signData(
  //             signerAddress2,
  //             signerAddress3,
  //             privateKey3,
  //             Buffer.from("addDelegate").toString("hex") +
  //               stringToBytes32("attestor") +
  //               stripHexPrefix(signerAddress2) +
  //               leftPad(new BN(86400).toString(16))
  //           );
  //           tx1 = await didReg.addDelegateSigned(
  //             signerAddress2,
  //             sig.v,
  //             sig.r,
  //             sig.s,
  //             hextoBytes32,
  //             signerAddress2,
  //             86400,
  //             { from: signerAddress }
  //           );
  //           block1 = await getBlock(tx1.receipt.blockNumber);
  //         });
  //         it("validDelegate should be true", async () => {
  //           let valid = await didReg.validDelegate(
  //             signerAddress2,
  //             hextoBytes32,
  //             signerAddress2
  //           );
  //           assert.equal(valid, true, "assigned delegate correctly");
  //         });
  //         it("should sets changed to transaction block", async () => {
  //           const latest = await didReg.changed(signerAddress2);
  //           assert.equal(latest.toNumber(), tx1.receipt.blockNumber);
  //         });
  //         it("should create DIDDelegateChanged event", () => {
  //           let event = tx1.logs[0];
  //           assert.equal(event.event, "DIDDelegateChanged");
  //           assert.equal(
  //             event.args.identity.toUpperCase(),
  //             signerAddress2.toUpperCase()
  //           );
  //           assert.equal(bytes32ToString(event.args.delegateType), "attestor");
  //           assert.equal(event.args.delegate, delegate);
  //           assert.equal(event.args.validTo.toNumber(), block1.timestamp + 86400);
  //           assert.equal(
  //             event.args.previousChange.toNumber(),
  //             previousChange1.toNumber()
  //           );
  //         });
  //       });
  //     });
  //   });

  //   describe("revokeDelegate()", () => {
  //     describe("using signature", () => {
  //       describe("as current owner", () => {
  //         let tx;
  //         before(async () => {
  //           previousChange = await didReg.changed(signerAddress2);
  //           const sig = await signData(
  //             signerAddress2,
  //             signerAddress3,
  //             privateKey3,
  //             Buffer.from("revokeDelegate").toString("hex") +
  //               stringToBytes32("attestor") +
  //               stripHexPrefix(signerAddress2)
  //           );
  //           tx = await didReg.revokeDelegateSigned(
  //             signerAddress,
  //             sig.v,
  //             sig.r,
  //             sig.s,
  //             hextoBytes32,
  //             signerAddress2,
  //             { from: signerAddress }
  //           );
  //           block = await getBlock(tx.receipt.blockNumber);
  //         });
  //         it("validDelegate should be false", async () => {
  //           const hex = web3.utils.asciiToHex("attestor");
  //           const valid = await didReg.validDelegate(
  //             signerAddress2,
  //             web3.utils.hexToBytes(hex),
  //             signerAddress2
  //           );
  //           assert.equal(valid, false, "revoked delegate correctly");
  //         });
  //         it("should sets changed to transaction block", async () => {
  //           const latest = await didReg.changed(signerAddress);
  //           assert.equal(latest, tx.receipt.blockNumber);
  //         });
  //         it("should create DIDDelegateChanged event", () => {
  //           const event = tx.logs[0];
  //           assert.equal(event.event, "DIDDelegateChanged");
  //           assert.equal(
  //             event.args.identity.toUpperCase(),
  //             signerAddress.toUpperCase()
  //           );
  //           assert.equal(bytes32ToString(event.args.delegateType), "attestor");
  //           assert.equal(event.args.delegate, delegate);
  //           assert.isBelow(
  //             event.args.validTo.toNumber(),
  //             Math.floor(Date.now() / 1000) + 1
  //           );
  //           assert.equal(
  //             event.args.previousChange.toNumber(),
  //             previousChange.toNumber()
  //           );
  //         });
  //       });
  //     });
  //   });

  //   describe("revokeAttribute()", () => {
  //     describe("using signature", () => {
  //       describe("as current owner", () => {
  //         let tx;
  //         before(async () => {
  //           previousChange = await didReg.changed(signerAddress);
  //           const sig = await signData(
  //             signerAddress,
  //             signerAddress2,
  //             privateKey2,
  //             Buffer.from("revokeAttribute").toString("hex") +
  //               stringToBytes32(someKey) +
  //               Buffer.from(someValue).toString("hex")
  //           );
  //           tx = await didReg.revokeAttributeSigned(
  //             signerAddress,
  //             sig.v,
  //             sig.r,
  //             sig.s,
  //             someKeyBytes,
  //             valueInBytes,
  //             { from: signerAddress }
  //           );
  //           block = await getBlock(tx.receipt.blockNumber);
  //         });
  //         it("should sets changed to transaction block", async () => {
  //           const latest = await didReg.changed(signerAddress);
  //           assert.equal(latest, tx.receipt.blockNumber);
  //         });
  //         it("should create DIDDelegateChanged event", () => {
  //           const event = tx.logs[0];
  //           assert.equal(event.event, "DIDAttributeChanged");
  //           assert.equal(
  //             event.args.identity.toUpperCase(),
  //             signerAddress.toUpperCase()
  //           );
  //           assert.equal(bytes32ToString(event.args.name), someKey);
  //           assert.equal(event.args.value, valueHex);
  //           assert.equal(event.args.validTo.toNumber(), 0);
  //           assert.equal(
  //             event.args.previousChange.toNumber(),
  //             previousChange.toNumber()
  //           );
  //         });
  //       });
  //     });
  //   });
});
