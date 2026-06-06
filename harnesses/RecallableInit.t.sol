// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/Test.sol";
import {OpenInitializer} from "../corpus/vulnerable/OpenInitializer.sol";
import {GuardedInitializer} from "../corpus/safe/GuardedInitializer.sol";

/// @notice Dynamic proof for eip7702-recallable-initializer (V2). An unguarded initializer can be
///         called a second time to seize a delegated account. Two-way: OpenInitializer is
///         re-initializable; GuardedInitializer rejects the second call.
contract RecallableInitHarness is Test {
    address internal constant LEGIT = address(0x600D);
    address internal constant ATTACKER = address(0xA11CE);

    function test_openInitializer_isReinitializable() public {
        Vm.Wallet memory eoa = vm.createWallet("victim");
        OpenInitializer impl = new OpenInitializer();
        vm.signAndAttachDelegation(address(impl), eoa.privateKey);

        OpenInitializer(eoa.addr).initialize(LEGIT);
        assertEq(OpenInitializer(eoa.addr).owner(), LEGIT, "first init sets the legit owner");

        // attacker re-initializes -> seizes the account.
        vm.prank(ATTACKER);
        OpenInitializer(eoa.addr).initialize(ATTACKER);
        assertEq(OpenInitializer(eoa.addr).owner(), ATTACKER, "recallable initializer: account seized by re-init");
    }

    function test_guardedInitializer_blocksReinit() public {
        Vm.Wallet memory eoa = vm.createWallet("victim2");
        GuardedInitializer impl = new GuardedInitializer();
        vm.signAndAttachDelegation(address(impl), eoa.privateKey);

        GuardedInitializer(eoa.addr).initialize(LEGIT);
        vm.prank(ATTACKER);
        vm.expectRevert(bytes("already initialized"));
        GuardedInitializer(eoa.addr).initialize(ATTACKER);
    }
}
