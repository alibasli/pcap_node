#!/usr/bin/env node

var app = require('express')();
var http = require('http').Server(app);
var io = require('socket.io')(http);

// index.html dosyası istemcilere gönderiliyor...
app.get('/', function(req, res){
  res.sendFile(__dirname + '/index.html');
});

http.listen(8001, function(){
  console.log('listening on 127.0.0.1:8001');
});
/////////////////////////////////////
var pcap = require("pcap"), pcap_session;//,tcp_tracker = new pcap.TCPTracker();
    
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

    // Print all devices, currently listening device prefixed with an asterisk
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

/////--------mongo db connections----------------

var should = require("should"); //  It keeps your test code clean, and your error messages helpful.
var monk = require("monk"); // a framework that makes accessing MongoDb really easy

var db = monk('localhost/exampleDb');
should.exists(db);
var collection = db.get("test3");
should.exists(collection);
getOldMessage();

//-------------get old packet-----------------------
 
function getOldMessage(){	
/*	collection.find({}, { limit : 100 },function(err, rows){
        if (err)
            console.log(err);
        else{
			for (var i = 0; i < rows.length; i++) {
				io.emit('chat message',rows[i].saddr +" --> "+rows[i].daddr );
			}
		}
    }); 
   */ 
}
// Listen for packets, decode them, and feed the simple printer.  No tricks..
var lotsOfDocs=[{'saddr':'.','daddr':'.','sayi':'0'}];
pcap_session.on("packet", function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet);
  //  var header = packet.pcap_header;
   // var ret = header.tv_sec + "." + rpad(header.tv_usec, 6) + " " + rpad(header.len + "B", 5) + " ";
   // io.emit('chat message',packet.payload.toString()); //tüm paketleri sockete yönlendir.

    if(packet.payload.payload){		
		//lotsOfDocs.push(packet.payload.payload.saddr.toString());
		ipControl(packet.payload.payload.saddr.toString(),packet.payload.payload.daddr.toString());
		//lotsOfDocs.push({'saddr':packet.payload.payload.saddr.toString(),'daddr':packet.payload.payload.daddr.toString()});
	  //  collection.insert(lotsOfDocs, {w:1}, function(err, result) {});	  	 
	  //  io.emit('chat message',packet.payload.payload.saddr.toString() +"->"+ packet.payload.payload.daddr.toString());	
	}
   else {}
   
});
function ipControl(saddr,daddr){
	for(var i=0;i<lotsOfDocs.length;i++) {
		if(saddr==lotsOfDocs[i]['saddr']){
			var sayi = lotsOfDocs[i]['sayi'];
			sayi++;
			if(sayi>10){
				io.emit('chat message',saddr);
			}			
			lotsOfDocs[i]['sayi'] = sayi;
			return;
		}
	}
	lotsOfDocs.push({'saddr':saddr,'daddr':daddr,"sayi":"1"});	
	return;
}
function timerJson() {	
	for(var i=0;i<lotsOfDocs.length;i++) {
		console.log("saddr:"+lotsOfDocs[i]['saddr']+"--sayi--"+lotsOfDocs[i]['sayi']);
	}
	lotsOfDocs=[{'saddr':'.','daddr':'.','sayi':'0'}];
    timer = setTimeout(timerJson, 2000)
}
var timer = setTimeout(timerJson, 2000)
//------------------send packet to html with socket---------------------------------------
io.on('connection', function(socket)
{
    console.log('Bir kullanıcı bağlandı');

    socket.on('chat message', function(msg)
    {
        io.emit('chat message', msg);
    });
    socket.on('disconnect', function()
    {
        console.log('Kullanıcı ayrıldı...');
    });
});
