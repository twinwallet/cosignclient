'use strict';

var _ = require('lodash');

var request;
if (process && !process.browser) {
    request = require('request');
} else {
    request = require('browser-request');
}

var httpHelper = module.exports = function (params) {
    var args = _.clone(params, true);
    args.body = args.data;
    args.json = true;
    return {
        then: function (successCallback, errorCallback) {
            request(args, function (err, res, body) {
                if (err) return errorCallback(err);
                var response = {
                    data: res.body,
                    status: res.statusCode,
                    headers: res.headers,
                    config: undefined,
                    statusText: res.statusMessage
                };
                if (res.status < 200 || res.status >= 300)
                    return errorCallback(response);
                successCallback(response);
            });
        }
    }
};
