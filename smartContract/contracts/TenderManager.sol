pragma solidity ^0.5.16;
pragma experimental ABIEncoderV2;

contract TenderManager {
    enum State {CLOSED, OFFERS, PENDING, FINISHED}
    struct Offer {
        string name;
        string AESkey;
        string Offer;
    }
    
    struct Tender {
        string name;
        Offer[] offers;
        State state;
        bool isExisting;
        string RSAKey;
        string CloudKey;
        string SecretKey;
    }
    
    mapping(address => Tender) public Tenders;
    address[] tenderList;
    
    function    isExisting(address tenderAddress) public view returns(bool doesIndeed) {
        return Tenders[tenderAddress].isExisting;
    }
    
    function newTender(address tenderAddress) public returns (string memory rowNumber) {
        if (!isExisting(tenderAddress)) revert();
        Offer[] memory tmpList = new Offer[](0);
        Tender memory tempStruct = Tender(name, 1, tmp, true);
        Tenders[tenderAddress] = tempStruct;
        tenderList.push(tenderAddress);
    }
    
    function newOffer(address tenderAddress, string name,string linkKey, string linkOffer) {
        if (!isExisting(tenderAddress)) revert();
        Offer memory tempStruct = Offer(name, linkKey, linkOffer);
        Tenders[tenderAddress].offers.push(tempStruct);
    }
}