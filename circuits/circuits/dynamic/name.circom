// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../dep/utils.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/gates.circom";
include "../../dep/extract.circom";

/** 
 * This template extracts the name from the body and checks that it's formatted correctly
 * 3355 constraints]
 */
template nameRegex(msgBytes) {
    signal input in[msgBytes];
    signal input start; //for body = picLen - minPic + partLen - minPart
    signal input len;

    // values from bodyRegex
    var maxName = 61;

    assert(msgBytes < 65536); // because we use LessThan(16) gates to compare indices

    // check all elements of the input in the correct indices are in the regex (a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|-|'| )
    component eq[3][msgBytes];
    component lt[6][msgBytes];
    component and[2][msgBytes];

    for (var i = 0; i < msgBytes; i++) {
        // check characters in the range A-Z
        lt[0][i] = LessThan(8);
        lt[0][i].in[0] <== 64;
        lt[0][i].in[1] <== in[i];

        lt[1][i] = LessThan(8);
        lt[1][i].in[0] <== in[i];
        lt[1][i].in[1] <== 91;

        and[0][i] = AND();
        and[0][i].a <== lt[0][i].out;
        and[0][i].b <== lt[1][i].out;

        // check characters in the range a-z
        lt[2][i] = LessThan(8);
        lt[2][i].in[0] <== 96;
        lt[2][i].in[1] <== in[i];

        lt[3][i] = LessThan(8);
        lt[3][i].in[0] <== in[i];
        lt[3][i].in[1] <== 123;

        and[1][i] = AND();
        and[1][i].a <== lt[2][i].out;
        and[1][i].b <== lt[3][i].out;

        // space
        eq[0][i] = IsEqual();
        eq[0][i].in[0] <== in[i];
        eq[0][i].in[1] <== 32;

        // '
        eq[1][i] = IsEqual();
        eq[1][i].in[0] <== in[i];
        eq[1][i].in[1] <== 39;

        // -
        eq[2][i] = IsEqual();
        eq[2][i].in[0] <== in[i];
        eq[2][i].in[1] <== 45;

        // this is 1 when index >= len + start
        // the idea is that we should ignore the indices greater than len + start
        // because we don't need to assert anything about these characters
        lt[4][i] = LessThan(16);
        lt[4][i].in[0] <== len + start - 1;
        lt[4][i].in[1] <== i;

        // this is 1 when index < start. Again, the
        // check below won't constrain the type of character for indices of in before 
        // start
        lt[5][i] = LessThan(16);
        lt[5][i].in[0] <== i;
        lt[5][i].in[1] <== start;
        
        // if they are both false this will fail
        //rand[0][i].out, and[1][i].out, eq[0][i].out, eq[1][i].out, eq[2][i].out are mutually exclusive and so is lt[4][i].out, lt[5][i].out
        0 === (1 - and[0][i].out - and[1][i].out - eq[0][i].out - eq[1][i].out - eq[2][i].out) * (1 - lt[4][i].out - lt[5][i].out);
    }

    // extract characters between start and len + start
    signal masked[msgBytes];
    for (var i = 0; i < msgBytes; i++) {
        masked[i] <== in[i] * (1 - lt[4][i].out - lt[5][i].out);
    }

    // parse out the name using a double array. We extract maxName, the range of the start index is
    // msgBytes - maxName (i.e. any index in in[msgBytes] could be part of name).
    component nameExtract = UncertaintyExtraction(msgBytes - maxName, maxName, 0, msgBytes);
    nameExtract.indicatorLen <== start;
    for (var i = 0; i < msgBytes; i++) {
        nameExtract.in[i] <== masked[i];
    }

    signal output out[maxName];
    for (var i = 0; i < maxName; i++){
        out[i] <== nameExtract.out[i];
    }
}
