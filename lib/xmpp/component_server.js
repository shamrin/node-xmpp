var sys = require('sys');
var net = require('net');
var EventEmitter = require('events').EventEmitter;
var crypto = require('crypto');

var Connection = require('./connection').Connection;
var JID = require('./jid').JID;
var ltx = require('ltx');

var NS_COMPONENT = 'jabber:component:accept';

/* Accepts incoming Component Protocol connections (e.g. from Transports)
 * params: jid, password, host (optional, localhost by default), port
 */
function ComponentServer(params, listener) {
    EventEmitter.call(this);
    var self = this;

    if (typeof params.jid == 'string')
        this.jid = new JID(params.jid);
    else
        this.jid = params.jid;
    this.password = params.password;
    this.componentJid = this.jid.domain;
    if(listener) {
        this.on('connection', listener);
    }

    net.createServer(function(inStream) {
        self.acceptConnection(inStream);
    }).listen(params.port, params.host || '::');
};

sys.inherits(ComponentServer, EventEmitter);
exports.ComponentServer = ComponentServer;

ComponentServer.prototype.acceptConnection = function(socket) {
    var inStream = new ComponentConnection(socket, this);
    var self = this;

    // adapted from connection.js:Connection constructor
    var proxyEvent = function(event) {
        inStream.on(event, function() {
	    var args = Array.prototype.slice.call(arguments);
	    args.unshift(event);
	    self.emit.apply(self, args);
        });
    };
    'stanza rawStanza sent streamStart error'.split(' ').forEach(function(e) {
        proxyEvent(e);
    });

    // Unhandled 'error' events will trigger exceptions, don't let that happen:
    //socket.addListener('error', function() { });
    //inStream.addListener('error', function() { });

    this.setupStream(inStream);
};

// XXX uncomment, see router.js
//ComponentServer.prototype.maxStanzaSize = 65536;  // 64 KB, by convention
//ComponentServer.prototype.keepAlive = 30 * 1000;  // 30s
//ComponentServer.prototype.streamTimeout = 5 * 60 * 1000;  // 5min

ComponentServer.prototype.setupStream = function(stream) {
    stream.streamFrom = this.componentJid;
    /*stream.maxStanzaSize = this.maxStanzaSize;
    StreamShaper.attach(stream.socket, this.rateLimit);
    stream.socket.setKeepAlive(true, this.keepAlive);
    IdleTimeout.attach(stream.socket, this.streamTimeout);
    stream.socket.addListener('timeout', function() {
                           stream.error('connection-timeout');
                       });*/
};

function ComponentConnection(socket, server) {
    var self = this;
    Connection.call(this, socket);
    this.server = server;
    this.streamId = generateId();
    this.xmlns[''] = NS_COMPONENT;
    this.startParser();
    this.authed = false;
    this.password = server.password;

    this.on('streamStart', function(attrs) {
        if(attrs.to !== self.streamFrom) {
            self.error('host-unknown', attrs.to + ' is not allowed here');
        } else {
            self.startStream();
        }
    });
    this.on('rawStanza', function(stanza) {
        if(self.authed) {
            self.emit('stanza', stanza);
        } else if(stanza.is('handshake', NS_COMPONENT)) {
            if(stanza.getText() === sha1_hex(self.streamId + self.password)) {
                self.send(new ltx.Element('handshake'));
                self.authed = true;
                self.server.emit('connection', self);
            } else {
                self.error('not-authorized', 'authentication failed');
            }
        }
    });
}

sys.inherits(ComponentConnection, Connection);

// XXX from server.js
function generateId() {
    var r = new Buffer(16);
    for(var i = 0; i < r.length; i++) {
        r[i] = 48 + Math.floor(Math.random() * 10);  // '0'..'9'
    }
    return r.toString();
};

// XXX from component.js
function sha1_hex(s) {
    var hash = crypto.createHash('sha1');
    hash.update(s);
    return hash.digest('hex');
}
