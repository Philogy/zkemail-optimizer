// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {Test} from "forge-std/Test.sol";
import {VerifierApp} from "src/VerifierApp.sol";

/// @author philogy <https://github.com/philogy>
contract VerifierTest is Test {
    VerifierApp verifier;

    function setUp() public {
        verifier = new VerifierApp();
    }

    function testVerify() public {
        verifier.verify(new uint[](0), "");
    }
}
