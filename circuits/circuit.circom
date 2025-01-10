pragma circom 2.0.0;
include "./commitment_hasher.circom";

template CommitmentRevealScheme(){
    // Public inputs
    signal input nullifierHash;
    signal input commitmentHash;
    
    
    // private inputs
    signal input nullifier;
    signal input secret;
    
    
    

    component commitmentHasher = CommitmentHasher();
    
    commitmentHasher.nullifier <== nullifier;
    commitmentHasher.secret <== secret;

    // Check if the nullifierHash and commitment are valid
    commitmentHasher.nullifierHash === nullifierHash;
    commitmentHasher.commitment === commitmentHash;

    

    

    

}

component main {public [nullifierHash,commitmentHash]} = CommitmentRevealScheme();
