
import { rbigint, generateCommitmentHash, generateNullifierHash,buildHashImplementation } from "../lib/index.js";

/**
 * This is a test input, generated for the starting circuit.
 * If you update the inputs, you need to update this function to match it.
 */
export async function getInput(){
    await buildHashImplementation();
    
    const secret = rbigint();
    const nullifier = rbigint();
    
    
    const commitmentHash = await generateCommitmentHash(nullifier, secret);
    const nullifierHash = await generateNullifierHash(nullifier);
    
    return {secret, nullifier, nullifierHash, commitmentHash,}
}

// Assert the output for hotreload by returning the expected output
// Edit this to fit your circuit
export async function getOutput() {
    return { out: 0 }
}

        