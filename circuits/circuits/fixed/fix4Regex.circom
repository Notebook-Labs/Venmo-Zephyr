// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

/** 
 * This template verifies a fixed section of html
 * More information can be found in the documentation
 * All equality testing so 0 constraints - all just labelling
 */
template fix4Regex() {
    signal input in[150];
    var fixed[150] = [34,47,62,13,10,32,32,32,32,32,32,32,32,32,32,32,61,50,48,13,10,13,10,32,32,32,32,32,32,32,32,32,32,32,32,60,33,45,45,32,97,109,111,117,110,116,32,45,45,62,13,10,32,32,32,32,32,32,32,32,32,32,32,61,50,48,13,10,32,32,32,32,32,32,32,32,32,32,32,32,60,115,112,97,110,32,115,116,121,108,101,61,51,68,34,102,108,111,97,116,58,114,105,103,104,116,59,34,62,13,10,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,61,50,48,13,10,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,45,32,36];
    // check input matches fixed
    for (var i = 0; i < 150; i++) {
        (in[i] - fixed[i]) * fixed[i] === 0;
    }
}



