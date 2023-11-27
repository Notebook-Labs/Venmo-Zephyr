// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../fixed/fix0Regex.circom";
include "../fixed/fix1Regex.circom";
include "../fixed/fix2Regex.circom";
include "../fixed/fix3Regex.circom";
include "../fixed/fix4Regex.circom";
include "../fixed/fix5Regex.circom";
include "../fixed/fix6Regex.circom";
include "../dynamic/name.circom";
include "../dynamic/amount.circom";
include "../../dep/extract.circom";

/** 
 * This is the main template for verifying the body of the venmo email. It extracts 7 fixed length blocks
 * and checks them in fixed. It also passes blocks of variable length into amountRegex.circom and
 * nameRegex.circom.
 * 67k constraints
 */
template BodyRegex(msgBytes) {
    signal input msg[msgBytes];

    signal input partLen; // 150-182 the length of the --part things at the start 
    signal input picLen; // 50-125
    signal input nameLen; // assume 3 - 61 (30 char max for first and last name + space)
    signal input dateLen; // assume 14 - 18
    signal input privacyLen; // 31-33
    signal input amountLen;// 4-10 assume value < $100,000
    signal input paymentLen; // assume 180-700 - length of the uncertainty after fix5 before the payment ID begins (i.e. the info about payment from bank etc.)

    // the ranges are all known at compile time and represent the amount of uncertainty in the indices of the end of each variable component
    // i.e. partRange is the absolute value of the difference of the first possible index part could end at and the last possible index part could end at

    // all of these are inclusive
    var minPart = 150;
    var maxPart = 182;
    var partRange = maxPart - minPart + 1; // variance in the index at the end of part - 33
    
    // fix 0 is before pic and after part
    var minPic = 50; // min string is s3.amazonaws.com/venmo/no-image.gif" al=\r\nt=3D"" st
    var maxPic = 125; // max string is pics.venmo.com/73474704-293c-4aae-8f2a-=\r\n5074ccc68935?width=3D100&amp;height=3D100&amp;photoVersion=3D3" alt=3D"" st=
    var picRange = partRange + maxPic - minPic; // variance in the index at the end of pic - 108
    
    // fix 1 is before name and after pic
    var minName = 3;
    var maxName = 61;
    var nameRange = picRange + maxName - minName; // variance in the index at the end of name - 166

    // fix 2 is before date and after namr
    var minDate = 14;
    var maxDate = 18;
    var dateRange = nameRange + maxDate - minDate; // variance in the index at the end of date - 170

    // fix 3 is before privacy and after date
    var minPrivacy = 31;
    var maxPrivacy = 33; 
    var privacyRange = dateRange + maxPrivacy - minPrivacy; // variance in the index at the end of privacy - 172

    // fix 4 is before amount and after privacy
    var minAmount = 4; // amount len is 4 for 0.00
    var maxAmount = 10; // amount len is 10 for 100,000.00
    var amountRange = privacyRange + maxAmount - minAmount; // variance in the index at the end of amount - 178

    // fix 5 is before payment and after amount
    var minPayment = 180;
    var maxPayment = 700;
    var paymentRange = amountRange + maxPayment - minPayment; // variance in the index at the end of id - 698
    
    // fix 6 is after payment
    var fix0Len = 1553;
    var fix1Len = 869;
    var fix2Len = 528;
    var fix3Len = 170;
    var fix4Len = 150;
    var fix5Len = 1495;
    var fix6Len = 930; // length of payment ID to extract

    // to prevent out of bounds indexing and the payment extracting from nullifiers
    assert(msgBytes >= fix0Len + fix1Len + fix2Len + fix3Len + fix4Len + fix5Len + fix6Len + maxPart + maxPic + maxName + maxDate + maxPrivacy + maxAmount + maxPayment);
    
    signal in[msgBytes];
    for (var i = 0; i < msgBytes; i++) {
        in[i] <== msg[i];
    }

    // Assert that partLen is less than 2^8-1
    component partCheck = MaxMinCheck(8, minPart, maxPart);
    partCheck.inLen <== partLen;

    // Assert picLen is less than 2^7-1 and in the range
    component picCheck = MaxMinCheck(7, minPic, maxPic);
    picCheck.inLen <== picLen;

    // Assert nameLen is less than 2^6-1 and in the range
    component nameCheck = MaxMinCheck(6, minName, maxName);
    nameCheck.inLen <== nameLen;

    // Assert dateLen is less than 2^5-1 and in the range
    component dateCheck = MaxMinCheck(5, minDate, maxDate);
    dateCheck.inLen <== dateLen;

    // Constrain privacy to be less than 2^6-1 and in the range
    component privacyCheck = MaxMinCheck(6, minPrivacy, maxPrivacy);
    privacyCheck.inLen <== privacyLen;

    // Constrain amount to be less than 2^4-1 and in the range
    component amountCheck = MaxMinCheck(4, minAmount, maxAmount);
    amountCheck.inLen <== amountLen;

    // Constrain paymentLen to be less than 2^10-1 and in the range
    component paymentCheck = MaxMinCheck(10, minPayment, maxPayment);
    paymentCheck.inLen <== paymentLen;


    // Extract the first fixed component
    signal fix0Indicator <== partLen - minPart;
    component fix0Extract = UncertaintyExtraction(partRange, fix0Len, minPart, msgBytes);
    fix0Extract.indicatorLen <== fix0Indicator;
    for (var i = 0; i < msgBytes; i++) {
        fix0Extract.in[i] <== in[i];
    }

    // Run fix0 through the fix0regex
    component fix0regex = fix0Regex();
    for (var i = 0; i < fix0Len; i++) {
        fix0regex.in[i] <== fix0Extract.out[i];
    }

    // No need to verify the pic string

    // Extract fix1 which then extracts both the venmoID (of recipient) and the sender's venmo ID
    var fix1Min = fix0Len + minPart + minPic;
    signal fix1Indicator <== fix0Indicator + picLen - minPic;

    component fix1Extract = UncertaintyExtraction(picRange, fix1Len, fix1Min, msgBytes);
    fix1Extract.indicatorLen <== fix1Indicator; // the additional length to be added to fix1Min to find when fix11 starts;
    
    for (var i = 0; i < msgBytes; i++) {
        fix1Extract.in[i] <== in[i];
    }

    component fix1regex = fix1Regex();
    for (var i = 0; i < fix1Len; i++) {
        fix1regex.in[i] <== fix1Extract.out[i];
    }

    signal output venmoID[19];
    for (var i = 0; i < 19; i++) {
        venmoID[i] <== fix1regex.venmoID[i];
    }

    signal output senderID[19];
    for (var i = 0; i < 19; i++) {
        senderID[i] <== fix1regex.senderID[i];
    }

    var nameMin = fix1Min + fix1Len; // min index at which name could begin
    component nameRegex = nameRegex(nameRange + minName);

    for (var i = 0; i < nameRange + minName; i++) {
        nameRegex.in[i] <== in[nameMin + i];
    }

    // lengths are needed to index name within input to nameRegex
    nameRegex.start <== picLen - minPic + partLen - minPart;
    nameRegex.len <== nameLen;

    // nameRegex pads the name with 0's to make it maxName long
    signal output recipientName[maxName];
     for (var i = 0; i < maxName; i++) { // maybe should only extract to nameLen
        recipientName[i] <== nameRegex.out[i];
    }

    // 
    // Regex the second fixed component and get claim ID
    //
    var fix2Min = nameMin + minName;
    signal fix2Indicator <== fix1Indicator + nameLen - minName;

    component fix2Extract = UncertaintyExtraction(nameRange, fix2Len, fix2Min, msgBytes);
    fix2Extract.indicatorLen <== fix2Indicator; 
    for (var i = 0; i < msgBytes; i++) {
        fix2Extract.in[i] <== in[i];
    }

    component fix2regex = fix2Regex();
    for (var i = 0; i < fix2Len; i++) {
        fix2regex.in[i] <== fix2Extract.out[i];
    }

    signal output claimId;
    claimId <== fix2regex.claimId;

    // Regex the third fixed component
    var fix3Min = fix2Len + fix2Min + minDate;
    signal fix3Indicator <== fix2Indicator + dateLen - minDate;

    component fix3Extract = UncertaintyExtraction(dateRange, fix3Len, fix3Min, msgBytes);
    fix3Extract.indicatorLen <== fix3Indicator; 
    for (var i = 0; i < msgBytes; i++) {
        fix3Extract.in[i] <== in[i];
    }

    component fix3regex = fix3Regex();
    for (var i = 0; i < fix3Len; i++) {
        fix3regex.in[i] <== fix3Extract.out[i];
    }

    // Length of privacy
    var privacyMin = fix3Min + fix3Len;

    // Regex the fourth fixed component
    var fix4Min = privacyMin + minPrivacy;
    signal fix4Indicator <== fix3Indicator + privacyLen - minPrivacy;

    component fix4Extract = UncertaintyExtraction(privacyRange, fix4Len, fix4Min, msgBytes);
    fix4Extract.indicatorLen <== fix4Indicator; 
    for (var i = 0; i < msgBytes; i++) {
        fix4Extract.in[i] <== in[i];
    }

    component fix4regex = fix4Regex();
    for (var i = 0; i < fix4Len; i++) {
        fix4regex.in[i] <== fix4Extract.out[i];
    }

    // Regex the amount
    component amountRegex = amountRegex(amountRange + minAmount);

    var amountMin = fix4Min + fix4Len; 
    for (var i = 0; i < amountRange + minAmount; i++) {
        amountRegex.in[i] <== in[amountMin + i];
    }

    // lengths required to index amount within input to amountRegex
    amountRegex.start <== partLen - minPart + picLen - minPic + nameLen - minName + dateLen - minDate + privacyLen - minPrivacy;
    amountRegex.len <== amountLen;

    signal output amount;
    amount <== amountRegex.out;

    // Regex the fifth fixed component
    var fix5Min = amountMin + minAmount;
    signal fix5Indicator <== fix4Indicator + amountLen - minAmount;

    component fix5Extract = UncertaintyExtraction(amountRange, fix5Len, fix5Min, msgBytes);
    fix5Extract.indicatorLen <== fix5Indicator;
    for (var i = 0; i < msgBytes; i++) {
        fix5Extract.in[i] <== in[i];
    }

    component fix5regex = fix5Regex();
    for (var i = 0; i < fix5Len; i++) {
        fix5regex.in[i] <== fix5Extract.out[i];
    }
 
    // we include in fix6Min the minPayment, and add the payment lengths to fix6Indicator
    var fix6Min = fix5Min + fix5Len + minPayment;
    signal fix6Indicator <== fix5Indicator + paymentLen - minPayment;

    component fix6Extract = UncertaintyExtraction(paymentRange, fix6Len, fix6Min, msgBytes);
    fix6Extract.indicatorLen <== fix6Indicator;
    for (var i = 0; i < msgBytes; i++) {
        fix6Extract.in[i] <== in[i];
    }

    signal output paymentID[19];
    component fix6regex = fix6Regex();

    // output payment ID for the nullifier calculated in venmoEmailFinal
    // passing it in to fix6rege to verify the ID is correctly formatted and all numbers
    for (var i = 0; i < fix6Len; i++) {
        fix6regex.in[i] <== fix6Extract.out[i];
    }

    for (var i = 0; i < 19; i++) {
        paymentID[i] <== fix6regex.paymentID[i];
    }

    signal output protection <== fix6regex.protection;
}

