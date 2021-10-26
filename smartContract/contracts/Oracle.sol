pragma solidity >= 0.5.0 < 0.6.0;

import "github.com/provable-things/ethereum-api/provableAPI_0.5.sol";

contract DieselPrice is usingProvable {

    uint public dieselPriceUSD;
    address public owner;

    event LogNewDieselPrice(string price);
    event LogNewProvableQuery(string description);

    constructor()
        public
    {
        owner = msg.sender;
        update(); // First check at contract creation...
    }

    function __callback(
        bytes32 _myid,
        string memory _result
    )
        public
    {
        require(msg.sender == provable_cbAddress());
        emit LogNewDieselPrice(_result);
        dieselPriceUSD = parseInt(_result, 2); // Let's save it as cents...
        // Now do something with the USD Diesel price...
    }

    function update()
        public
        payable
    {
        emit LogNewProvableQuery("Provable query was sent, standing by for the answer...");
        provable_query("URL", "xml(https://www.fueleconomy.gov/ws/rest/fuelprices).fuelPrices.diesel");
    }
}