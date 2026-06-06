// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/Test.sol";
import {NoNonceSig} from "../corpus/vulnerable/NoNonceSig.sol";
import {NonceSig} from "../corpus/safe/NonceSig.sol";

/// @notice Dynamic proof for eip7702-missing-nonce (V5). A signature-gated transfer with no nonce
///         is replayable: one authorization drains the account repeatedly. Two-way: NoNonceSig
///         sends twice from a single signature; NonceSig rejects the replay.
contract SigReplayHarness is Test {
    address payable internal constant RECIPIENT = payable(address(0xBEEF));

    function test_noNonce_signatureReplays() public {
        Vm.Wallet memory eoa = vm.createWallet("owner");
        NoNonceSig impl = new NoNonceSig();
        vm.signAndAttachDelegation(address(impl), eoa.privateKey);

        // the delegated account's owner is the EOA itself (slot 0); fund it.
        vm.store(eoa.addr, bytes32(uint256(0)), bytes32(uint256(uint160(eoa.addr))));
        vm.deal(eoa.addr, 10 ether);

        uint256 amount = 1 ether;
        bytes32 digest = keccak256(abi.encodePacked(RECIPIENT, amount));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoa.privateKey, digest);

        NoNonceSig(eoa.addr).oneTimeSend(RECIPIENT, amount, v, r, s);   // first authorized send
        NoNonceSig(eoa.addr).oneTimeSend(RECIPIENT, amount, v, r, s);   // REPLAY the same signature

        assertEq(RECIPIENT.balance, 2 * amount, "missing nonce: one signature drained the account twice");
    }

    function test_nonce_blocksReplay() public {
        Vm.Wallet memory eoa = vm.createWallet("owner2");
        NonceSig impl = new NonceSig();
        vm.signAndAttachDelegation(address(impl), eoa.privateKey);

        vm.store(eoa.addr, bytes32(uint256(0)), bytes32(uint256(uint160(eoa.addr))));
        vm.deal(eoa.addr, 10 ether);

        uint256 amount = 1 ether;
        uint256 nonce = 1;
        bytes32 digest = keccak256(abi.encodePacked(RECIPIENT, amount, nonce));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoa.privateKey, digest);

        NonceSig(eoa.addr).send(RECIPIENT, amount, nonce, v, r, s);
        vm.expectRevert(bytes("replayed"));
        NonceSig(eoa.addr).send(RECIPIENT, amount, nonce, v, r, s);
    }
}
