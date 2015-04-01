#!/usr/bin/env node

var app = require('express')();
var http = require('http').Server(app);
var io = require('socket.io')(http);

// index.html dosyası istemcilere gönderiliyor...
app.get('/', function(req, res){
  res.sendFile(__dirname + '/index.html');
});

http.listen(8001, function(){
  console.log('listening on 127.0.01:8001');
});
/////////////////////////////////////
//#!/usr/bin/env node

var pcap = require("pcap"), pcap_session,tcp_tracker = new pcap.TCPTracker();
    
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

// libpcap's internal version numnber
//console.log(pcap.lib_version);

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


tcp_tracker.on('session', function (session) {
	//bağlantı olduğunda bağlantıyı decode et
  io.emit('chat message',"Start of session between " + session.src_name + " and " + session.dst_name);
  io.emit('chat message',"  -src : " + session.src
  + "  -dst:  " + session.dst
  + "  -syn_time:  " + session.syn_time
  + "  -state:  " + session.state
  + " - key:  " + session.key
  + "  -send_isn:  " + session.send_isn
  + "  -send_window_scale:  " + session.send_window_scale
  + "  -send_packets:  " + session.send_packets
  + "  -send_acks:  " + session.send_acks
  + "  -send_retrans:  " + session.send_retrans
  + "  -send_next_seq:  " + session.send_next_seq
  + "  -send_acked_seq:  " + session.send_acked_seq
  + "  -send_bytes_ip:  " + session.send_bytes_ip
  + "  -send_bytes_tcp:  " + session.send_bytes_tcp
  + "  -send_bytes_payload:  " + session.send_bytes_payload

  + " -recv_isn:  " + session.recv_isn
  + " -recv_window_scale:  " + session.recv_window_scale
  + " -recv_packets: " + session.recv_packets
  + " -recv_acks:  " + session.recv_acks
  + " -recv_retrans:  " + session.recv_retrans
  + " -recv_next_seq:  " + session.recv_next_seq
  + " -recv_acked_seq:  " + session.recv_acked_seq
  + " -recv_bytes_ip:  " + session.recv_bytes_ip
  + " -recv_bytes_tcp:  " + session.recv_bytes_tcp
  + " -recv_bytes_payload  " + session.recv_bytes_payload);    
    
  session.on('end', function (session) {
     // console.log("End of TCP session between " + session.src_name + " and " + session.dst_name);
     io.emit('chat message',"End of TCP session between " + session.src_name + " and " + session.dst_name);
      
  });
});
// Listen for packets, decode them, and feed the simple printer.  No tricks..
pcap_session.on("packet", function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet);
   // var header = packet.pcap_header;
      tcp_tracker.track_packet(packet);
   // var ret = header.tv_sec + "." + rpad(header.tv_usec, 6) + " " + rpad(header.len + "B", 5) + " ";

    io.emit('chat message',packet.payload.toString()); //tüm paketleri sockete yönlendir.
   // console.log(packet.payload.toString());
});


//////////////////

io.on('connection', function(socket)
{
    console.log('Bir kullanıcı bağlandı');

    socket.on('chat message', function(msg)
    {
        io.emit('chat message', msg); //paketleri index.html e gönder
    });
    socket.on('disconnect', function()
    {
        console.log('Kullanıcı ayrıldı...');
    });
});
