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

//decode packet
tcp_tracker.on('session', function (session) {
  console.log("Start of session between " + session.src_name + " and " + session.dst_name);
  console.log("src  " + session.src);
  console.log("dst  " + session.dst);
  console.log("syn_time  " + session.syn_time);
  console.log("state  " + session.state);
  console.log("key  " + session.key);
  console.log("send_isn  " + session.send_isn);
  console.log("send_window_scale  " + session.send_window_scale);
  console.log("send_packets  " + session.send_packets);
  console.log("send_acks  " + session.send_acks);
  console.log("send_retrans  " + session.send_retrans);
  console.log("send_next_seq  " + session.send_next_seq);
  console.log("send_acked_seq  " + session.send_acked_seq);
  console.log("send_bytes_ip  " + session.send_bytes_ip);
  console.log("send_bytes_tcp  " + session.send_bytes_tcp);
  console.log("send_bytes_payload  " + session.send_bytes_payload);

  console.log("recv_isn  " + session.recv_isn);
  console.log("recv_window_scale  " + session.recv_window_scale);
  console.log("recv_packets  " + session.recv_packets);
  console.log("recv_acks  " + session.recv_acks);
  console.log("recv_retrans  " + session.recv_retrans);
  console.log("recv_next_seq  " + session.recv_next_seq);
  console.log("recv_acked_seq  " + session.recv_acked_seq);
  console.log("recv_bytes_ip  " + session.recv_bytes_ip);
  console.log("recv_bytes_tcp  " + session.recv_bytes_tcp);
  console.log("recv_bytes_payload  " + session.recv_bytes_payload);
  console.log("------------------------------------------------------");
    io.emit('chat message',"src  " + session.src  + " dst  " + session.dst);
  session.on('end', function (session) {
      console.log("End of TCP session between " + session.src_name + " and " + session.dst_name);
      
  });
});
// Listen for packets, decode them, and feed the simple printer.  No tricks..
pcap_session.on("packet", function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet);
   // var header = packet.pcap_header;
      tcp_tracker.track_packet(packet);
   // var ret = header.tv_sec + "." + rpad(header.tv_usec, 6) + " " + rpad(header.len + "B", 5) + " ";

    io.emit('chat message',packet.payload.toString());
   // console.log(packet.payload.toString());
});


//////////////////

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
