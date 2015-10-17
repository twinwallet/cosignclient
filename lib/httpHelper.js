'use strict';

var _ = require('lodash');

var request;
if (process && !process.browser) {
    request = require('request');
} else {
    request = require('browser-request');
}

var httpHelper = module.export = function (params) {
    var args = _.clone(params, true);
    args.body = args.data;
    args.json = true;
    return {
        then: function (successCallback, errorCallback) {
            request(args, function (err, res, body) {
                // TODO build response for callbacks
                throw new Error('Not implemented yet');
            });
        }
    }
};
