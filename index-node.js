'use strict';

var bwclient = require('bitcore-wallet-client');
var CSClient = require('./lib/csclient');

module.export = CSClient;

CSClient.create = function (opts) {
    opts = opts || {};
    if (!opts.bwutils) {
        opts.bwutils = bwclient.Utils;
    }
    if (!opts.sjcl) {
        opts.bwutils = bwclient.sjcl;
    }
    if (!opts.httpHelper) {
        opts.httpHelper = require('./lib/httpHelper');
    }
    return new CSClient(opts);
};


