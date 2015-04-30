var pcap = require("pcap"), pcap_session;
var db = require('./mongo');

var packet,lotsOfDocs=[{'saddr':'.','daddr':'.','sayi':'0'}];

module.exports = function(io){
	pcap_session.on("packet", function (raw_packet) {
		packet = pcap.decode.packet(raw_packet);  
     
		if(packet.payload.payload){	
			io.emit('packet',packet.payload.toString()); 
			try{
				db.savePacket(packet);
			} catch (err) {
				console.log("packet DB");
			}
			try{
				ipControl(packet.payload.payload.saddr.toString(),packet.payload.payload.daddr.toString(),io);
			} catch (err) {
				console.log(err);
			}			
		}
		else {} 
	});
};
function ipControl(saddr,daddr,io){
	for(var i=0;i<lotsOfDocs.length;i++) {
		if(saddr==lotsOfDocs[i]['saddr']){
			var sayi = lotsOfDocs[i]['sayi'];
			sayi++;
			// ip sayısı 100 ü aştıysa atak olduğunu bildir.
			if(sayi>100){
				io.emit('attack', saddr);
				lotsOfDocs[i]['sayi']=0;
				return;
			}			
			lotsOfDocs[i]['sayi'] = sayi;
			return;
		}
	}
	lotsOfDocs.push({'saddr':saddr,'daddr':daddr,"sayi":"1"});	
	return;
}
function timerJson() {	
	// Her 2 sn de lotsOfDocs ip'leri sıfırla.
	lotsOfDocs=[{'saddr':'.','daddr':'.','sayi':'0'}];	
    timer = setTimeout(timerJson, 2000)
}
var timer = setTimeout(timerJson, 2000);
    
if (process.argv.length > 4) {
    console.error("usage: simple_capture interface filter");
    console.error("Examples: ");
    console.error('  simple_capture "" "tcp port 80"');
    console.error('  simple_capture eth1 ""');
    console.error('  simple_capture lo0 "ip proto \\tcp and tcp port 80"');
    process.exit(1);
}

function offline() {
    pcap_session = pcap.createOfflineSession(process.argv[2], process.argv[3]);
}

function online() {
    pcap_session = pcap.createSession(process.argv[2], process.argv[3]);

    console.log("Capture device list: ");
    pcap_session.findalldevs().forEach(function (dev) {
        var ret = "    ";
        if (pcap_session.device_name === dev.name) {
            ret += "* ";
        }
        ret += dev.name + " ";
        if (dev.addresses.length > 0) {
            ret += dev.addresses.filter(function (address) {
                return address.addr;
            }).map(function (address) {
                return address.addr + "/" + address.netmask;
            }).join(", ");
        } else {
            ret += "no address";
        }
       // console.log(ret);
    });

   // console.log();
}

try {
    var stat = require("fs").statSync(process.argv[2]);
    if (stat && stat.isFile()) {
        offline();
    } else {
        online();
    }
} catch (err) {
    online();
}

function rpad(num, len) {
    var str = num.toString();
    while (str.length < len) {
        str += " ";
    }
    return str;
}

var DNSCache = require("pcap/dns_cache");
var dns_cache = new DNSCache();

var IPv4Addr = require("pcap/decode/ipv4_addr");
IPv4Addr.prototype.origToString = IPv4Addr.prototype.toString;
IPv4Addr.prototype.toString = function() {
    return dns_cache.ptr(this.origToString());
};


