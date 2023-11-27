# Venmo Payment Circuits

When a seller places a sell order, they will post a commitment to their Venmo ID. These IDs are unique, and are used to verify that the buyer paid 
the correct person. A buyer will first place a claim on the Zephyr orderbook contract, the buyer will then send the Venmo payment with the correct note (correspinding
to the claim) to the correct ID. A seller must also specify if they are a buisness account or not. If they are not a buisness account, the buyer must send the payment without purchase protections.

## Constraints

| Constraints        | Templating | Hashing & Signature | Total |
|--------------------|-------|---------|------------|
| Venmo   | 224,647 | 6,038,916| 6,263,563 |

## General Circuit Paradigm

We build our circuits with two intentions in mind:
- (**Completeness** & **Soundness**) Given the current Venmo email template, honest provers' emails should always generate valid proofs and malicious provers should never be able to generate a valid proof.
- (**Safeguard**) Given the slightest change in the email template by Venmo, the proof should always fail. We made this design choice because it is impossible to predict was potential exploits could come up if Venmo changed their template therefore we would rather all proofs fail and we create a new circuit adapted for the new template.

Given this, we detail that the following parts of the circuit are done for completeness and soundness:
- Verifying the pair of RSA signaturess.
- Computing the hash of the body.
- Extracting the body hash from the header and checking equality with the body hash and between headers.
Extracting the relevant information from the body.

The following parts are done as a safeguard:
- Constraining all the fix html sections of the Venmo body.
- Extracting the name and amount from the subject and checking against the values extracted from the body.

## Zephyr-Venmo Licensing

Select components of Zephyr-Venmo, which are marked with "SPDX-License-Identifier: BUSL-1.1", were launched under a Business Source License 1.1 (BUSL 1.1).

The license limits use of the Zephyr source code in a commercial or production setting until January 1st, 2026. After this, the license will convert to a general public license. This means anyone can fork the code for their own use — as long as it is kept open source.

In addition, certain parts of Zephyr-Venmo are derived from other sources and are separately licensed under the GNU General Public License (GPL-3.0-only). These components are explicitly marked with "SPDX-License-Identifier: GPL-3.0-only" and are subject to the terms of the GNU GPL. The full text of the GPL license can be found in the LICENSE-GPL file in the root directory of this project.