'use strict';

var CSClient = require('./lib/csclient');

module.export = CSClient;

CSClient.create = function (opts) {
    opts = opts || {};
    if (!opts.bwutils) {
        opts.bwutils = require('bitcore-wallet-utils');
    }
    if (!opts.httpHelper) {
        opts.httpHelper = require('./lib/httpHelper');
    }
    return new CSClient(opts);
};


