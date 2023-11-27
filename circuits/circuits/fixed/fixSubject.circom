// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

/**
 * This template is used to check that the first 79 characters of the header matches the following
 * from:Venmo <venmo@venmo.com>\r\n
 * reply-to:Venmo No-reply <no-reply@venmo.com>\r\n
 * to:
 * All equality testing so 0 constraints - all just labelling
 */
template SubjectFix0Regex() {
    signal input in[79];
    var fixed[79] = [102,114,111,109,58,86,101,110,109,111,32,60,118,101,110,109,111,64,118,101,110,109,111,46,99,111,109,62,13,10,114,101,112,108,121,45,116,111,58,86,101,110,109,111,32,78,111,45,114,101,112,108,121,32,60,110,111,45,114,101,112,108,121,64,118,101,110,109,111,46,99,111,109,62,13,10,116,111,58];
    
    // check input matches fixed
    for (var i = 0; i < 79; i++) {
        in[i] === fixed[i];
    }
}

/**
 * This template is used to check that a specific part of the header starts with "subject:You Paid "
 * All equality testing so 0 constraints - all just labelling
 */
template SubjectFix1Regex() {
    signal input in[19];
    var fixed[19] = [13, 10, 115, 117, 98, 106, 101, 99, 116, 58, 89, 111, 117, 32, 112, 97, 105, 100, 32];
    // check input matches fixed
    for (var i = 0; i < 19; i++) {
        in[i] === fixed[i];
    }
}


/**
 * Checks ' $'
 */
template SubjectFix2Regex() {
    signal input in[2];
    var fixed[2] = [32, 36];
    for (var i = 0; i < 2; i++) {
        in[i] === fixed[i];
    }
}


/**
 * Checks '\r\n'
 */
template SubjectFix3Regex() {
    signal input in[2];
    var fixed[2] = [13, 10];
    for (var i = 0; i < 2; i++) {
        in[i] === fixed[i];
    }
}