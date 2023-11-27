// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/gates.circom";
include "../fixed/fixSubject.circom";
include "../dynamic/amount.circom";
include "../dynamic/name.circom";
include "../../dep/extract.circom";

/** 
 * This template is used to check the format of the email header and extract the name and amount.
 * The beginning of a 'you paid' email header looks like:
 *
 * from:Venmo <venmo@venmo.com>
 * reply-to:Venmo No-reply <no-reply@venmo.com>
 * to:natmasfenyan@gmail.com
 * subject:You paid Solal Afota $1.00
 *
 * Where there is \r\n between each pairs of line. This regex will first equality constrain the characters:
 * from:Venmo <venmo@venmo.com>\r\nreply-to:Venmo No-reply <no-reply@venmo.com>\r\nto: 
 * and then skips emailLen characters.It then checks "\r\nsubject:You paid", extracts the name, verifies
 * ' $' and then extracts amount and then checks \r\n.
 * Total constraints - 28k
 */
template SubjectRegex(msgBytes) {
    signal input in[msgBytes];
    signal input emailLen;
    signal input nameLen;
    signal input amountLen;

    var fix0Len = 79;
    var fix1Len = 19;
    var fix2Len = 2;
    var fix3Len = 2;
    var minEmail = 0;
    var maxEmail = 320;
    var emailRange = maxEmail - minEmail + 1;
    var minName = 3;
    var maxName = 61;
    var nameRange = emailRange + maxName - minName;
    var minAmount = 4;
    var maxAmount = 10;
    var amountRange = nameRange + maxAmount - minAmount;

    // Assert that partLen is less than 2^8-1
    component emailCheck = MaxMinCheck(9, minEmail, maxEmail);
    emailCheck.inLen <== emailLen;

    component subjectFix0Regex = SubjectFix0Regex();
    for (var i = 0; i < fix0Len; i++) {
        subjectFix0Regex.in[i] <== in[0 + i];
    }


    component emailUncertainty = UncertaintyExtraction(emailRange, fix1Len, fix0Len + minEmail, msgBytes);
    emailUncertainty.indicatorLen <== emailLen - minEmail;
    for (var i = 0; i < msgBytes; i++) {
        emailUncertainty.in[i] <== in[i];
    }
    signal fix1Array[fix1Len];
    for (var i = 0; i < fix1Len; i++) {
        fix1Array[i] <== emailUncertainty.out[i];
    }


    component subjectFix1Regex = SubjectFix1Regex();
    for (var i = 0; i < fix1Len; i++) {
        subjectFix1Regex.in[i] <== fix1Array[0 + i];
    }


    signal output name[maxName];
    component nameRegex = nameRegex(nameRange + minName);
    for (var i = 0; i < nameRange + minName; i++) {
        nameRegex.in[i] <== in[minEmail + fix1Len + fix0Len + i];
    }
    nameRegex.start <== emailLen - minEmail;
    nameRegex.len <== nameLen;
    for (var i = 0; i < maxName; i++) {
        name[i] <== nameRegex.out[i];
     }


    component nameUncertainty = UncertaintyExtraction(nameRange, fix2Len, fix0Len + minEmail + fix1Len + minName, msgBytes);
    nameUncertainty.indicatorLen <== nameLen - minName + emailLen - minEmail;
    for (var i = 0; i < msgBytes; i++) {
        nameUncertainty.in[i] <== in[i];
    }
    signal fix2Array[fix2Len];
    for (var i = 0; i < fix2Len; i++) {
        fix2Array[i] <== nameUncertainty.out[i];
    }


    component subjectFix2Regex = SubjectFix2Regex();
    for (var i = 0; i < fix2Len; i++) {
        subjectFix2Regex.in[i] <== fix2Array[0 + i];
    }


    signal output amount;
    component amountRegex = amountRegex(amountRange + minAmount);
    for (var i = 0; i < amountRange + minAmount; i++) {
        amountRegex.in[i] <== in[fix0Len + fix1Len + minEmail + fix2Len + minName + i];
    }
    amountRegex.start <== emailLen - minEmail + nameLen - minName;
    amountRegex.len <== amountLen;
    amount <== amountRegex.out;


    component amountUncertainty = UncertaintyExtraction(amountRange, fix3Len, fix0Len + minEmail + fix1Len + minName + fix2Len + minAmount, msgBytes);
    amountUncertainty.indicatorLen <== nameLen - minName + emailLen - minEmail + amountLen - minAmount;
    for (var i = 0; i < msgBytes; i++) {
        amountUncertainty.in[i] <== in[i];
    }
    signal fix3Array[fix3Len];
    for (var i = 0; i < fix3Len; i++) {
        fix3Array[i] <== amountUncertainty.out[i];
    }


    component subjectFix3Regex = SubjectFix3Regex();
    for (var i = 0; i < fix3Len; i++) {
        subjectFix3Regex.in[i] <== fix3Array[0 + i];
    }
}