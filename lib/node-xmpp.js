var Client = require('./xmpp/client').Client;
var Component = require('./xmpp/component').Component;
var JID = require('./xmpp/jid').JID;
var Router = require('./xmpp/router');
var ltx = require('ltx');
var ComponentServer = require('./xmpp/component_server').ComponentServer;

exports.Client = Client;
exports.Component = Component;
exports.JID = JID;
exports.XML = ltx;
exports.Element = ltx.Element;
exports.Router = Router.Router;
exports.ComponentServer =  ComponentServer;
