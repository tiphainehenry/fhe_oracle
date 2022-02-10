pragma solidity ^0.5.16;
pragma experimental ABIEncoderV2;

import "./ElectToolbox.sol";
import "./ProvableAPI_0.5.sol";


contract TenderManager {
    enum State {CLOSED, OFFERS, PENDING, FINISHED}
    struct OfferList {
        string name;
        string c_key; //RSA_of_AESkey
        string c_offer; //AES_of_FHE_of_Offer
        address respondent;
    }
    
    struct Tender {
        string name;
        string RSAPubKey; //From Oracle
        string offers="";
 
        OfferList[] offerList;
        State state;
        bool isExisting;
    }

    mapping(address => Tender) public Tenders;
    address[] tenderList;
    
    function isExisting(address tenderAddress) public view returns(bool doesIndeed) {
        return Tenders[tenderAddress].isExisting;
    }
    
    function newTender(address tenderAddress) public returns (string memory rowNumber) {
        if (!isExisting(tenderAddress)) revert();
        Offer[] memory tmpList = new Offer[](0);
        Tender memory tempStruct = Tender(name, 1, tmp, true);
        Tenders[tenderAddress] = tempStruct;
        tenderList.push(tenderAddress);
    }
    
    function newOffer(address tenderAddress, string name,string c_key, string c_offer) {
        if (!isExisting(tenderAddress)) revert();
        OfferList memory tempStruct = OfferList(name, c_key, c_offer, tenderAddress);

        string tempStruct = "{name:"+name+",c_key:"+c_key+"c_offer:"+c_offer+"}";

        Tenders[tenderAddress].offers.push(tempStruct);

    }





    /// @notice Callback function. Emits to the user the best profiles retrieved based on the QoS computation.
    /// @dev This function is triggered by the oracle.
    /// @param myid The binary array of required attributes (set of filtering criteria)
    /// @param result best profiles retrieved by the oracle.
    function __callback(bytes32 myid, string memory result) public {
        if (msg.sender != provable_cbAddress()) revert();

        bestAlloc = result;

        emit BestAlloc("Matching", bestAlloc);
    }


    function askOracleComparison(address tenderAddress) public returns (string memory offers){
        // send oracle request for comparison

            /// compute qos via oracle
            if (provable_getPrice("URL") > address(this).balance) {
                emit LogNewProvableQuery(
                    "Provable query was NOT sent, please add some ETH to cover for the query fee"
                );
            } else {
                emit LogNewProvableQuery(
                    "Provable query was sent, standing by for the answer.."
                );
                string memory str_offers = ElectToolbox.list2string(Tenders[tenderAddress].offers);
                string memory url =
                    string(
                        abi.encodePacked(
                            "https://qosapi.herokuapp.com/api/qos?offers=",
                            offers
                        )
                    );
                provable_query("URL", url);
            }


        return "200";
    }


}