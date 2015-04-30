var should = require("should"); 
var monk = require("monk");

var db = monk('localhost/pcap');
should.exists(db);
var collection = db.get("packes");
should.exists(collection);

exports.savePacket=function(packet){
	collection.insert(packet, function(err, doc){
	    if(err)
	    { 
			console.log("PAKET KAYDEDİLEMEDİ !"); 
		}
	    else
	    { 
	    }
	    });
};
