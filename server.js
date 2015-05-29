#!/usr/bin/env node

var express = require('express');
var app = express();
var http = require('http').Server(app);
var io = require('socket.io')(http);
var pcap = require("pcap");

app.use(express.static(__dirname + '/JS'));
 
app.get('/', function(req, res){
  // index.html dosyası istemcilere gönderiliyor...
  res.sendFile(__dirname + '/index.html');
});

http.listen(8001, function(){
  console.log('listening on : 127.0.0.1:8001');
});

require('./pcap')(io);

