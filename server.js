#!/usr/bin/env node

var app = require('express')();
var http = require('http').Server(app);
var io = require('socket.io')(http);
var pcap = require("pcap");


app.get('/', function(req, res){
  // index.html dosyası istemcilere gönderiliyor...
  res.sendFile(__dirname + '/index.html');
});

http.listen(8001, function(){
  console.log('listening on : 127.0.0.1:8001');
});

require('./pcap')(io);

