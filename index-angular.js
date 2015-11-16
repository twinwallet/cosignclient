'use strict';

var cscModule = angular.module('cscModule', []);

var CSClient = require('./lib/csclient');

cscModule.constant('MODULE_VERSION', '0.4.0');

/**
 * Service factory.
 * The dependency 'bwcService' is defined in the project angular-bitcore-wallet-client.
 */
cscModule.factory('cscService', ['$http', 'bwcService', function ($http, bwcService) {
    var service = {};

    var config = {
        baseUrl: 'http://localhost:3001/cosign/api',
        walletUtils: bwcService.getUtils()
    };

    service.setBaseUrl = function (url) {
        config.baseUrl = url;
    };

    service.setWalletUtils = function (wu) {
        config.walletUtils = wu;
    };

    service.getCSClient = function (opts) {
        opts = opts || {};
        opts.baseUrl = opts.baseUrl || config.baseUrl;
        opts.httpRequest = $http;
        opts.bwutils = config.walletUtils;

        return new CSClient(opts);
    };

    return service;
}]);
