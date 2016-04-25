'use strict';

var cscModule = angular.module('cscModule', []);

var CSClient = require('./lib/csclient');
var NoticeBoard = require('./lib/noticeBoard');
var NoticeExtBackup = require('./lib/noticeExtBackup');

cscModule.constant('MODULE_VERSION', '0.8.0');

/**
 * Service factory.
 * The dependency 'bwcService' is defined in the project angular-bitcore-wallet-client.
 */
cscModule.factory('cscService', ['$http', 'bwcService', function ($http, bwcService) {
    var service = {};

    var defaults = {
        baseUrl: 'http://localhost:3001/cosign/api',
        bwclibs: {
            Bitcore: bwcService.getBitcore(),
            Utils: bwcService.getUtils(),
            sjcl: bwcService.getSJCL()
        }
    };

    service.setBaseUrl = function (url) {
        defaults.baseUrl = url;
    };

    service.setWalletUtils = function (wu) {
        defaults.walletUtils = wu;
    };

    service.getCSClient = function (opts) {
        opts = opts || {};
        opts.baseUrl = opts.baseUrl || defaults.baseUrl;
        opts.httpRequest = $http;
        opts.bwclibs = angular.extend(opts.bwclibs || {}, defaults.bwclibs, opts.bwclibs);

        return new CSClient(opts);
    };

    service.createNoticeBoard = NoticeBoard.create;

    service.getNoticeExtensionBackup = function (noticeBoard) {
        return new NoticeExtBackup(noticeBoard);
    };

    return service;
}]);
