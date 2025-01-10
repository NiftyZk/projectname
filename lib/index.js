
import { utils } from "ffjavascript";
import crypto from "crypto";
import assert from "assert";
import { buildPoseidon } from "circomlibjs";
import { groth16 } from "snarkjs";
    

/**
 * @returns {bigint} Returns a random bigint
 */
export function rbigint() { return utils.leBuff2int(crypto.randomBytes(31)) };
   
//The hash implementation is stored local scoped to avoid rebuilding it multiple times
let hashimpl = null;

/**
 * Builds the hashing algorithm
 */
export async function buildHashImplementation() {
    if (!hashimpl) {
        const hasher = await buildPoseidon();
        hashimpl = { hasher };
    }
}

/**
* @param args {Array<bigint>} - A list of bigint to compute the hash
* @returns {bigint} Returns the poseidon hash
*/
export async function poseidon(args) {
    const hashBytes = hashimpl.hasher(args);
    const hash = hashimpl.hasher.F.toString(hashBytes);
    return BigInt(hash);
}

/**
 * 
 * @param nullifier {string | bigint} - The nullifier used for the circuit
 * @param secret {string | bigint} - The secret used for the circuit 
 * @returns {bigint} Returns a poseidon hash
 */
export async function generateCommitmentHash(nullifier, secret){
    return await poseidon([BigInt(nullifier),BigInt(secret)])
}
/**
 * @param nullifier {string | bigint} - The nullifier used for the circuit
 * @returns {bigint} Returns the poseidon hash 
 */
export async function generateNullifierHash(nullifier){
    return await poseidon([BigInt(nullifier)])
}


    
/**
 * @param {Object} options - The arguments for the compute proof
 * @param {bigint | string} options.secret - The secret used for the commitment reveal scheme
 * @param {bigint | string} options.nullifier
 * 
 * @param {Object} options.publicInputs
 * @param {bigint | string} options.publicInputs.commitmentHash
 * @param {bigint | string} options.publicInputs.nullifierHash - The nullifier used for mitigating replay attacks * 
 * @param {Object | undefined} options.snarkArtifacts - Paths to the artifacts used for generating the proof. If undefined, default values will be used. It allows for file system paths and urls.
 * @param {string} options.snarkArtifacts.wasmFilePath - Path to the generated witness file
 * @param {string} options.snarkArtifacts.zkeyFilePath - Path to the generated zKey file
 */ 
export async function computeProof({secret, nullifier, publicInputs, snarkArtifacts}){
    const input = {
      //Private inputs
      secret,
      nullifier,
      
      
      //Public inputs
      ...publicInputs        
    }

    if(!snarkArtifacts){
        snarkArtifacts = {
            wasmFilePath: "circuits/compiled/circuit_js/circuit.wasm", 
            zkeyFilePath: "circuits/compiled/zkeys/circuit_final.zkey",
        }
       }

    const {proof, publicSignals} = await groth16.fullProve(
        input,
        snarkArtifacts.wasmFilePath,
        snarkArtifacts.zkeyFilePath
       )

    return {proof, publicSignals}
}
    /**
 * Verifies a SnarkJS proof.
 * @param verificationKey The zero-knowledge verification key.
 * @param fullProof The SnarkJS full proof.
 * @returns {boolean} True if the proof is valid, false otherwise.
 */

export function verifyProof({verificationKey, proof, publicSignals }) {
    return groth16.verify(
        verificationKey,
        publicSignals,
        proof,
    );
}
