// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/sha256/sha256.circom";
include "../dep/sha256.circom";
include "../dep/rsa.circom";
include "../dep/base64.circom";
include "../dep/utils.circom";
include "../dep/modulusHash.circom";
include "./wrappers/body.circom";
include "./wrappers/subject.circom";
include "../dep/bodyHashRegex.circom";

/** 
 * This is the main template which coordinates the verification of the Venmo email receipt.
 * The template will verify two RSA signatures of the header: one from Venmo and one from Amazonses.
 * The template will run a regular expression on both beaders to extract the recipient name and amount to ensure they match.
 * The template will extract the body hash from both headers and verify that they match
 * The template will then calculate the hash of the body and verify that it matches the body hash extracted from the header.
 * The template will then run a "regular expression" on the body to ensure that it matches the expected format and to extract relevant infomration.
 * A nullifier is created by calculating the poseidon hash of the amount, payment ID, buyer ID, and seller ID
 * All outputs are then hashed using sha256 to produce a single output hash.
 *
 * Since the moduli and signatures are larger than the size of the field, we need to represent them as bigints
 * we use n and k are the biginteger parameters. This means that each value is represented as k, n-bit chunks.
 * we range check the moduli and signatures below. Additionaly, when testing these circuits we assume 114 <= n <= 121 and 9 <= k <= 17
 * which corresponds to the values for 1024 and 2048 RSA bit keys.
 * Furthermore, we assume that inPadded0, inPadded1, inBodyPadded is an array of bytes (we range check this below)
 * Finally, we assume that inLenPaddedBytes0, inLenPaddedBytes1, inBodyLenPaddedBytes are the length of the padded messages in bytes
 * and that they are multiples of 64: this get's checked in the sha256 template
 * We also assume that the variable lengths are within certain bounds. These bounds are checked at the start of the bodyRegex template. 
 * We detail them in the circom regex page of our docs.
 */
template VenmoVerify(maxHeaderBytes, maxBodyBytes, n, k, keyLenBytes) {

    // support for 1024, 2048 bit rsa keys
    assert(keyLenBytes >= 128);
    assert(keyLenBytes <= 256);
    assert(keyLenBytes % 64 == 0);

    assert(maxHeaderBytes % 64 == 0);
    assert(maxHeaderBytes > 0);
    assert(maxHeaderBytes < 2048); // Just to ensure maxHeaderBits is a field element. In practice can be larger
    
    assert(maxBodyBytes % 64 == 0);
    assert(maxBodyBytes > 0);
    assert(maxBodyBytes < 16000); // Just to ensure maxHeaderBits is a field element. In practice can be larger
    
    assert(n * k > keyLenBytes * 8); // ensure we have enough bits to store the modulus
    assert(k * 2 < 255); 
    assert(k >= 0);
    assert(n >= 0);
    assert(n < 122); // not a perfect bound but we need 2n + log(k) < 254 

    
    //
    // HASH FIRST HEADER FOR RSA SIGNATURE VERIFICATION
    // 

    // the header venmo signs with padding
    signal input inPadded0[maxHeaderBytes]; 
    signal input inLenPaddedBytes0; // length of in header data including the padding

    var maxHeaderBits = maxHeaderBytes * 8;
    component sha0 = Sha256(maxHeaderBits);

    // Need to input bits to Sha256. Also servers as a range check
    component inPadded0Bits[maxHeaderBytes];

    for (var i = 0; i < maxHeaderBytes; i++) {
        inPadded0Bits[i] = Num2Bits(8);
        inPadded0Bits[i].in <== inPadded0[i];

        for (var j = 0; j < 8; j++) {
            // we need to unflip the bits as sha0 treats the first bit as the MSB
            sha0.paddedIn[i*8+j] <== inPadded0Bits[i].out[7-j]; 
        }
    }

    sha0.inLenPaddedBits <== inLenPaddedBytes0 * 8;
    
    //
    // VERIFY VENMO RSA SIGNATURE
    //

    // venmo pubkey, verified with smart contract oracle
    signal input modulus0[k]; 
    signal input signature0[k];

    // range check the public key
    component modulus0RangeCheck[k];
    for (var i = 0; i < k; i++) {
        modulus0RangeCheck[i] = Num2Bits(n);
        modulus0RangeCheck[i].in <== modulus0[i];
    }

    // range check the signature
    component signature0RangeCheck[k];
    for (var i = 0; i < k; i++) {
        signature0RangeCheck[i] = Num2Bits(n);
        signature0RangeCheck[i].in <== signature0[i];
    }

    // verify the rsa signature of the first key
    component rsa0 = RSAVerify65537(n, k, keyLenBytes);
    for (var i = 0; i < 256; i++) {
        log(sha0.out[i]);
        rsa0.baseMessage[i] <== sha0.out[i];
    }
    for (var i = 0; i < k; i++) {
        rsa0.modulus[i] <== modulus0[i];
    }
    for (var i = 0; i < k; i++) {
        rsa0.signature[i] <== signature0[i];
    }

    //
    // HASH SECOND HEADER FOR RSA SIGNATURE VERIFICATION
    // 

    // padded header that Amazon SES signs, in bytes
    signal input inPadded1[maxHeaderBytes];
    signal input inLenPaddedBytes1; // length of in header data including the padding

    component sha1 = Sha256(maxHeaderBits);

    // Need to input bits to Sha256. Also servers as a range check
    component inPadded1Bits[maxHeaderBytes];

    for (var i = 0; i < maxHeaderBytes; i++) {
        inPadded1Bits[i] = Num2Bits(8);
        inPadded1Bits[i].in <== inPadded1[i];

        for (var j = 0; j < 8; j++) {
            // we need to unflip the bits as sha0 treats the first bit as the MSB
            sha1.paddedIn[i*8+j] <== inPadded1Bits[i].out[7-j]; 
        }
    }

    sha1.inLenPaddedBits <== inLenPaddedBytes1 * 8;

    //
    // VERIFY AMAZON SES RSA SIGNATURE
    //
    signal input modulus1[k];
    signal input signature1[k];

    // range check the public key
    component modulus1RangeCheck[k];
    for (var i = 0; i < k; i++) {
        modulus1RangeCheck[i] = Num2Bits(n);
        modulus1RangeCheck[i].in <== modulus1[i];
    }

    // range check the signature
    component signature1RangeCheck[k];
    for (var i = 0; i < k; i++) {
        signature1RangeCheck[i] = Num2Bits(n);
        signature1RangeCheck[i].in <== signature1[i];
    }

    // verify the rsa signature of the first key
    component rsa1 = RSAVerify65537(n, k, keyLenBytes);
    for (var i = 0; i < 256; i++) {
        log(sha1.out[i]);
        rsa1.baseMessage[i] <== sha1.out[i];
    }
    for (var i = 0; i < k; i++) {
        rsa1.modulus[i] <== modulus1[i];
    }
    for (var i = 0; i < k; i++) {
        rsa1.signature[i] <== signature1[i];
    }

    //
    // SUBJECT REGEX 0:
    //
    signal input nameLen; 
    signal input amountLen;
    signal input emailLen;

    component subjectRegex0 = SubjectRegex(maxHeaderBytes);
    for (var i = 0; i < maxHeaderBytes; i++) {
        subjectRegex0.in[i] <== inPadded0[i];
    }
    subjectRegex0.nameLen <== nameLen;
    subjectRegex0.amountLen <== amountLen;
    subjectRegex0.emailLen <== emailLen;

    //
    // SUBJECT REGEX 1:
    //
    component subjectRegex1 = SubjectRegex(maxHeaderBytes);
    for (var i = 0; i < maxHeaderBytes; i++) {
        subjectRegex1.in[i] <== inPadded1[i];
    }
    subjectRegex1.nameLen <== nameLen;
    subjectRegex1.amountLen <== amountLen;
    subjectRegex1.emailLen <== emailLen;

    //
    // EQUALITY CHECK SUBJECT REGEXES
    //
    subjectRegex0.amount === subjectRegex1.amount;

    var maxName = 61;
    for (var i = 0; i < maxName; i++) {
        log(subjectRegex0.name[i]);
        log(subjectRegex1.name[i]);
        subjectRegex0.name[i] === subjectRegex1.name[i];
    }

    //
    // BODY HASH REGEX 0: 
    //
    var lenShaB64 = 44;  
    component bodyHashRegex0 = BodyHashRegex(maxHeaderBytes, lenShaB64);
    for (var i = 0; i < maxHeaderBytes; i++) {
        bodyHashRegex0.msg[i] <== inPadded0[i];
    }

    //
    // BODY HASH REGEX 1: 
    //
    component bodyHashRegex1 = BodyHashRegex(maxHeaderBytes, lenShaB64);
    for (var i = 0; i < maxHeaderBytes; i++) {
        bodyHashRegex1.msg[i] <== inPadded1[i];
    }

    //
    // EQUALITY CHECK EXTRACT BODY HASHES
    //
    for (var i = 0; i < lenShaB64; i++) {
        log(bodyHashRegex0.bodyHashOut[i]);
        log(bodyHashRegex1.bodyHashOut[i]);
        bodyHashRegex0.bodyHashOut[i] === bodyHashRegex1.bodyHashOut[i];
    }

    //
    // HASH BODY ~3.5 million constraints
    //

    // bytes array of body characters with SHA padding
    signal input inBodyPadded[maxBodyBytes];
    signal input inBodyLenPaddedBytes;

    var maxBodyBits = maxBodyBytes * 8;
    component shaBody = Sha256(maxBodyBits);

    // Need to input bits to Sha256. Also servers as a range check
    component inBodyPaddedBits[maxBodyBytes];

    for (var i = 0; i < maxBodyBytes; i++) {
        inBodyPaddedBits[i] = Num2Bits(8);
        inBodyPaddedBits[i].in <== inBodyPadded[i];

        for (var j = 0; j < 8; j++) {
            // we need to unflip the bits as Sha256 treats the first bit as the MSB
            shaBody.paddedIn[i*8+j] <== inBodyPaddedBits[i].out[7-j]; 
        }
    }

    shaBody.inLenPaddedBits <== inBodyLenPaddedBytes * 8;

    //
    // VERIFY HASH OF BODY MATCHES BODY HASH EXTRACTED FROM HEADER 
    //
    component shaB64 = Base64Decode(lenShaB64); 
    for (var i = 0; i < lenShaB64; i++) {
        shaB64.in[i] <== bodyHashRegex0.bodyHashOut[i];
    }

    for (var i = 0; i < 256; i++) {
        log(shaBody.out[i]);
        shaB64.out[i] === shaBody.out[i];
    }

    //
    // BODY REGEX AND EXTRACTION
    //
    component bodyRegex = BodyRegex(maxBodyBytes);
    for (var i = 0; i < maxBodyBytes; i++) {
        bodyRegex.msg[i] <== inBodyPadded[i];
    }
    
    // These are range checked in BodyRegex
    signal input partLen; 
    signal input picLen; 
    signal input dateLen; 
    signal input privacyLen; 
    signal input paymentLen;

    bodyRegex.partLen <== partLen;
    bodyRegex.picLen <== picLen;
    bodyRegex.nameLen <== nameLen;
    bodyRegex.dateLen <== dateLen;
    bodyRegex.privacyLen <== privacyLen;
    bodyRegex.amountLen <== amountLen;
    bodyRegex.paymentLen <== paymentLen;
    
    //
    // EQUALITY CHECK NAME AND AMOUNT WITH SUBJECT
    //
    for (var i = 0; i < maxName; i++) {
        subjectRegex0.name[i] === bodyRegex.recipientName[i];
    }

    signal amount <== bodyRegex.amount;
    amount === subjectRegex0.amount; 

    //
    // PACK RECIPIENT ID, SENDER ID AND PAYMENT ID
    //
    signal packId <== Bytes2Packed(19, bodyRegex.venmoID);
    signal packSenderId <== Bytes2Packed(19, bodyRegex.senderID);   
    signal packPaymentId <== Bytes2Packed(19, bodyRegex.paymentID);

    //
    // RECIPIENT ID HASHING
    //
    signal input nonce; // salt for the hash to anonymise the recipient

    component venmoIdHasher = Poseidon(2);
    venmoIdHasher.inputs[0] <== packId; 
    venmoIdHasher.inputs[1] <== nonce;
    signal venmoIdHash <== venmoIdHasher.out;

    // 
    // HASH NULLIFIER 
    //
    component nullifierHasher = Poseidon(4); 
    nullifierHasher.inputs[0] <== packId; 
    nullifierHasher.inputs[1] <== packPaymentId;
    nullifierHasher.inputs[2] <== packSenderId;
    nullifierHasher.inputs[3] <== amount;
    
    //
    // HASH PUBLIC KEYS 
    //
    component shaMod = ModulusSha(n, k, keyLenBytes);
    for (var i = 0; i < k; i++) {
        shaMod.modulus0[i] <== modulus0[i];
    }

    for (var i = 0; i < k; i++) {
        shaMod.modulus1[i] <== modulus1[i];
    }

    //
    // COMPUTE THE OUTPUTTED COMMITMENT
    //
    // megaHash = H(modHash (256 bits) || VenmoHash (255 bits) || Protection (1 bit) || Nullifier (256 bits) || Prover (160 bits) || ClaimId (64 bits) || Amount (32 bits) || padding (512 bits))
    component megaHash = Sha256(1024);

    // add modulus hash to mega hash
    for (var i = 0; i < 256; i++) {
        megaHash.in[i] <== shaMod.out[i];
    }

    // add venmo id hash to mega hash
    component venmoBits256 = Num2Bits(256);
    venmoBits256.in <== venmoIdHash;
    for (var i = 0; i < 255; i++) {
        megaHash.in[256 + i] <== venmoBits256.out[255 - i];
    }

    log(venmoIdHash);

    // add protection to mega hash - removed num2bits(1) from here as was unnecessary 
    megaHash.in[511] <== bodyRegex.protection;


    log(bodyRegex.protection);

    // Add nullifier to mega hash
    component nullifierBits = Num2Bits(256);
    nullifierBits.in <== nullifierHasher.out;
    for (var i = 0; i < 256; i++) {
        megaHash.in[512 + i] <== nullifierBits.out[255 - i];
    }

    log(nullifierHasher.out);

    // add proverAddress to mega hash (this also acts as a range check)
    signal input proverAddress; //160 bits

    component proverBits160 = Num2Bits(160);
    proverBits160.in <== proverAddress;
    for (var i = 0; i < 160; i++) {
        megaHash.in[768 + i] <== proverBits160.out[159 - i];
    }
    log(proverAddress);

    // add claim to mega hash
    signal claimId <== bodyRegex.claimId;
    log(claimId);

    component claimBits64 = Num2Bits(64);
    claimBits64.in <== claimId;
    for (var i = 0; i < 64; i++) {
        megaHash.in[928 + i] <== claimBits64.out[63 - i];
    }

    // add amount to mega hash
    component amountBits32 = Num2Bits(32);
    amountBits32.in <== amount;
    for (var i = 0; i < 32; i++) {
        megaHash.in[992 + i] <== amountBits32.out[31 - i];
    }

    log(amount);

    signal output outputHash;

    component megaHashBits2Num = Bits2Num(253);
    for (var i = 0; i < 253; i++) {
        megaHashBits2Num.in[i] <== megaHash.out[252 - i];// need to add 253-i
    }

    outputHash <== megaHashBits2Num.out;
}

// can we decrease 9216?
component main = VenmoVerify(1024, 9216, 121, 9, 128); // this is inetended to be used for 1024