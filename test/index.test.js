
    import assert from "assert";
    import {computeProof, verifyProof} from "../lib/index";
    import fs from "fs";
    import { getInput } from "./input.js";

    it("Test commit-reveal scheme", async function(){
        const {secret,nullifier,commitmentHash,nullifierHash,} = await getInput();
        //When compiling the tests via `niftyzk verificationkey` the path of the zkey used is written into a file so you don't have to adjust the tests when using different zkeys
        const zkeyPath = fs.readFileSync("circuits/compiled/vk_meta.txt", "utf-8")
        const {proof, publicSignals} = await computeProof({

        secret, 
        nullifier,
         
        publicInputs: {
            commitmentHash, 
            nullifierHash,
            
        },

                snarkArtifacts: {             
                    wasmFilePath: "circuits/compiled/circuit_js/circuit.wasm", 
                    zkeyFilePath: zkeyPath,
                }
            })
            const verificationKeyFile = fs.readFileSync("circuits/compiled/verification_key.json", "utf-8");
            const verificationKey = JSON.parse(verificationKeyFile);
            const result = await verifyProof({verificationKey, proof, publicSignals})
            assert.equal(result, true)
        },50000)
    