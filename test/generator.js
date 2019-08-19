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

  async function signData(
    identity,
    signer,
    key,
    nonceBN,
    didRegistryContractAddress,
    data
  ) {
    // get the contract nonce - not the Blockchain nonce, replay attack prevention
    // const nonce = await didReg.nonce(signer);
    // console.log(nonce);
    const paddedNonce = leftPad(Buffer.from([nonceBN], 64).toString("hex"));
    const dataToSign =
      "1900" +
      stripHexPrefix(didRegistryContractAddress) +
      paddedNonce +
      stripHexPrefix(identity) +
      data;
    const hash = Buffer.from(sha3.buffer(Buffer.from(dataToSign, "hex")));
    const signature = ethutil.ecsign(hash, key);
    // const publicKey = ethutil.ecrecover(
    //   hash,
    //   signature.v,
    //   signature.r,
    //   signature.s
    // );
    return {
      r: "0x" + signature.r.toString("hex"),
      s: "0x" + signature.s.toString("hex"),
      v: signature.v
    };
  }

  describe("identityOwner()", () => {
    describe("using signature", () => {
      describe("as current owner", () => {
        it("generate the Signed Transaction", async () => {
          // CHANGE THE NONCE HERE FROM THE CONTRACT
          let nonce = 4; // increment with every signed message- get from contract
          //   let attrType = "Name"; // possible values  Name, PhoneNum, Ez-link CAN number, D/E Card IMM27
          //   let attrValue = "Hitesh";

          let attributes = [
            // {
            //   type: "Name",
            //   value: "Hitesh"
            // },
            {
              type: "PhoneNum",
              value: "989897779"
            },
            {
              type: "Ez-link CAN number",
              value: "HHHH"
            },
            {
              type: "D/E Card IMM27",
              value: "BBBB"
            }
          ];

          let didAddress = signerAddress3;
          let didOwner = signerAddress3; // in our case didAddress and didOwner will always be same
          let didOwnerPrivateKey = privateKey3;
          let didRegistryContractAddress =
            // "0x57c77a4e1485076cc53e160655c13b6b088a32a4";
            "0xbff29cafa45b4899778671df2fab0704427ce73f"; // Kaleido contract address

          let response = {
            publicKey: didAddress,
            didAddress: didAddress,
            attributes: []
          };

          for (let x of attributes) {
            let nonceBN = ethers.utils.bigNumberify(nonce);
            const sig = await signData(
              didAddress, // is the identity did address
              didOwner, // who is signing and current owner
              didOwnerPrivateKey, // signing addres pvt key,
              nonceBN, // auto incremented nonce of contract
              didRegistryContractAddress, // Kaleido contract address
              Buffer.from("setAttribute").toString("hex") + // which method to call
              stringToBytes32(x.type) + //the attribute Name
              Buffer.from(x.value).toString("hex") + // the attribute value
                leftPad(new BN(86400).toString(16)) // the attribute validity
            );

            let attr = {
              type: x.type,
              value: x.value,
              sigR: sig.r,
              sigV: sig.v,
              sigS: sig.s
            };
            response.attributes.push(attr);

            nonce++;
          }
          console.log(JSON.stringify(response, null, 2));
        });
      });
    });
  });
});
