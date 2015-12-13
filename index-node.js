'use strict';

var bwclient = require('bitcore-wallet-client');
var CSClient = require('./lib/csclient');

module.exports = CSClient;

CSClient.create = function (opts) {
    opts = opts || {};
    var bwclibs = opts.bwclibs || {};
    bwclibs.Bitcore = bwclibs.Bitcore || bwclient.Bitcore;
    bwclibs.Utils = bwclibs.Utils || bwclient.Utils;
    bwclibs.sjcl = bwclibs.sjcl || bwclient.sjcl;
    opts.bwclibs = bwclibs;
    opts.httpRequest = opts.httpRequest || require('./lib/httpHelper');

    return new CSClient(opts);
};


