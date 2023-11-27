// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/gates.circom";

/**
 * This template verifies a fixed section of html containing the payment ID
 * More information can be found in the documentation
 */
template fix6Regex() {
    signal input in[930];
    
    component lt[2][19];
    component and[19];

    // verify that paymentID is 19 consecutive digits between 0 and 9
    for (var i = 0; i < 19; i++) {
        lt[0][i] = LessThan(8);
        lt[0][i].in[0] <== 47;
        lt[0][i].in[1] <==  in[i];

        lt[1][i] = LessThan(8);
        lt[1][i].in[0] <==  in[i];
        lt[1][i].in[1] <== 58;

        and[i] = AND();
        and[i].a <== lt[0][i].out;
        and[i].b <== lt[1][i].out;

        and[i].out === 1;
    }

    // first 19 are payment ID
    var fixed[929] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,13,10,32,32,32,32,32,32,32,61,50,48,13,10,60,47,100,105,118,62,13,10,13,10,32,32,32,61,50,48,13,10,60,100,105,118,32,115,116,121,108,101,61,51,68,34,99,111,108,111,114,58,35,54,66,54,69,55,54,59,102,111,110,116,45,115,105,122,101,58,49,50,112,120,59,109,97,114,103,105,110,45,116,111,112,58,49,48,112,120,59,112,97,100,100,105,110,103,45,116,111,112,58,49,48,112,120,61,13,10,59,32,98,111,114,100,101,114,45,116,111,112,58,32,49,112,120,32,100,111,116,116,101,100,32,35,99,99,99,34,62,13,10,32,32,32,32,60,100,105,118,32,115,116,121,108,101,61,51,68,34,119,105,100,116,104,58,53,48,37,59,32,112,97,100,100,105,110,103,58,53,112,120,59,32,116,101,120,116,45,97,108,105,103,110,58,99,101,110,116,101,114,59,32,98,111,114,100,101,114,45,114,97,100,105,117,115,58,61,13,10,53,48,112,120,59,32,98,97,99,107,103,114,111,117,110,100,45,99,111,108,111,114,58,35,48,48,55,52,68,69,59,34,62,13,10,32,32,32,32,32,32,32,32,60,97,32,104,114,101,102,61,51,68,34,104,116,116,112,115,58,47,47,118,101,110,109,111,46,99,111,109,47,114,101,102,101,114,114,97,108,47,105,110,118,105,116,101,63,99,97,109,112,97,105,103,110,95,115,101,114,118,105,99,101,61,51,68,101,109,97,61,13,10,105,108,38,99,97,109,112,97,105,103,110,95,116,101,109,112,108,97,116,101,61,51,68,112,97,121,109,101,110,116,46,115,101,110,116,34,32,115,116,121,108,101,61,51,68,34,116,101,120,116,45,100,101,99,111,114,97,116,105,111,110,58,110,111,110,101,59,32,99,111,108,111,114,58,32,61,13,10,35,48,48,48,59,32,100,105,115,112,108,97,121,58,98,108,111,99,107,59,32,119,105,100,116,104,58,49,48,48,37,59,32,102,111,110,116,45,115,105,122,101,58,49,50,112,120,59,34,62,13,10,32,32,32,32,32,32,32,32,32,32,32,32,60,100,105,118,32,115,116,121,108,101,61,51,68,34,102,111,110,116,45,115,105,122,101,58,49,52,112,120,59,32,99,111,108,111,114,58,35,102,102,102,59,34,62,73,110,118,105,116,101,32,70,114,105,101,110,100,115,33,60,47,100,105,118,61,13,10,62,13,10,32,32,32,32,32,32,32,32,60,47,97,62,13,10,32,32,32,32,60,47,100,105,118,62,13,10,13,10,13,10,32,32,32,32,60,100,105,118,32,115,116,121,108,101,61,51,68,34,109,97,114,103,105,110,45,98,111,116,116,111,109,58,49,48,112,120,59,34,62,60,47,100,105,118,62,13,10,13,10,60,47,100,105,118,62,13,10,13,10,32,32,32,32,60,100,105,118,32,105,100,61,51,68,34,95,114,101,99,101,105,112,116,95,100,105,115,99,108,111,115,117,114,101,115,34,32,115,116,121,108,101,61,51,68,34,102,111,110,116,45,115,105,122,101,58,49,49,112,120,59,109,97,114,103,105,110,45,116,111,112,58,49,48,112,61,13,10,120,59,112,97,100,100,105,110,103,45,116,111,112,58,49,48,112,120,59,32,98,111,114,100,101,114,45,116,111,112,58,32,49,112,120,32,100,111,116,116,101,100,32,35,99,99,99,34,62,13,10,13,10,32,32,32,32,60,100,105,118,62,13,10,32,32,32,32,32,32,32,32,70,111,114,32,97,110,121,32,105,115,115,117,101,115,44,32,105,110,99,108,117,100,105,110,103,32,116,104,101,32,114,101,99,105,112,105,101,110,116,32,110,111,116,32,114,101,99,101,105,118,105,110,103,32,102,117,110,100,115,44,32,112,108,101,97,115,101,61,13,10,32,99,111,110,116,97,99,116,32,117,115,32,97,116,32,115,117,112,112,111,114,116,64,118,101,110,109,111,46,99,111,109,32,111,114,32,99,97,108,108,32,49,45,56,53,53,45,56,49,50,45,52,52,51,48,46];
    for (var i = 0; i < 929; i++) {
        (in[i] - fixed[i]) * fixed[i] === 0;
    }

    signal output paymentID[19];
    for (var i = 0; i < 19; i++) {
        paymentID[i] <== in[i];
    }


    //Section at the end are either:
    //purchase protection - For any issues, including the recipient not receiving funds, please=\r\ncontact us at support@venmo.com or call 1-855-812-4430.<br/><br/>As an obl=\r\nigor of this payment, PayPal, Inc. (855-812-4430) is liable for non-deliver=\r\ny or delayed delivery of your funds.<br/>
    //no protection -       For any issues, including the recipient not receiving funds, please=\r\ncontact us at support@venmo.com or call 1-855-812-4430.\r\n</div>
    // We check if the buyer turned on purchase protections
    0 === (in[929] - 13) * (in[929] - 60); // either /r or <

    component eq = IsEqual();
    eq.in[0] <== in[929];
    eq.in[1] <== 60;
    signal output protection <== eq.out;
}


