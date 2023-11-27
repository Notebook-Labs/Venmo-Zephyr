// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/gates.circom";

/** 
 * This template extracts the amount from the body and checks that it's formatted correctly
 * 6600 constraints
 */
template amountRegex(msgBytes) {
    signal input in[msgBytes];
    signal input start;
    signal input len;
    signal output out;


    assert(msgBytes < 65536); // because we use LessThan(16) gates to compare indices

    // first nameLen + dateLen chars are irrelevant, then should be of the format [0-9]*.[0-9][0-9]
    // can check a regex without needing states
    component lt[4][msgBytes];
    component eq[3][msgBytes];
    component and[3][msgBytes];
    component or[msgBytes];
    signal revealIndicator[msgBytes];
    signal position[msgBytes];
    for (var i = 0; i < msgBytes; i++) {
        // isolate values in the range of indices: start - 1 < i <start - 3
        lt[0][i] = LessThan(16);
        lt[0][i].in[0] <== start - 1;
        lt[0][i].in[1] <== i;

        lt[1][i] = LessThan(16);
        lt[1][i].in[0] <== i;
        lt[1][i].in[1] <== start + len - 3;

        and[0][i] = AND();
        and[0][i].a <== lt[0][i].out;
        and[0][i].b <== lt[1][i].out;

        //use the two equal gates to skip the full stop
        eq[0][i] = IsEqual();
        eq[0][i].in[0] <== i;
        eq[0][i].in[1] <==  start + len - 2;

        eq[1][i] = IsEqual();
        eq[1][i].in[0] <== i;
        eq[1][i].in[1] <== start + len - 1;

        // this signal outputs if the index is valid
        position[i] <== and[0][i].out + eq[0][i].out + eq[1][i].out;

        // check the value of the element is between 0-9
        lt[2][i] = LessThan(8);
        lt[2][i].in[0] <== 47;
        lt[2][i].in[1] <== in[i];

        lt[3][i] = LessThan(8);
        lt[3][i].in[0] <== in[i];
        lt[3][i].in[1] <== 58;

        and[1][i] = AND();
        and[1][i].a <== lt[2][i].out;
        and[1][i].b <== lt[3][i].out;

        // check for comma
        eq[2][i] = IsEqual();
        eq[2][i].in[0] <== in[i];
        eq[2][i].in[1] <== 44;

        // check that if the index is valid - element is either 0-9 or a comma (so fits the correct regex)
        or[i] = OR();
        or[i].a <== and[1][i].out;
        or[i].b <== eq[2][i].out;
        
        position[i] * (1 - or[i].out) === 0;

        // set the values which are right index and are between 0-9 (i.e. not a comma or some random char) to 1
        and[2][i] = AND();
        and[2][i].a <== and[1][i].out;
        and[2][i].b <==  position[i];

        revealIndicator[i] <== and[2][i].out;
    }

    // use the indicator to parse the amount into an output
    signal amount[msgBytes + 1];
    amount[0] <== 0;
    for (var i = 0; i < msgBytes; i++) {
        amount[i + 1] <== amount[i] + revealIndicator[i] * (9 * amount[i] + in[i] - 48);
    }

    out <== amount[msgBytes];
}