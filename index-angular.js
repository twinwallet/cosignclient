'use strict';

var cscModule = angular.module('cscModule', []);

var CSClient = require('./lib/csclient');
var NoticeBoard = require('./lib/noticeBoard');
var NoticeExtBackup = require('./lib/noticeExtBackup');

cscModule.constant('MODULE_VERSION', '0.7.0');

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
        var bwclibs = opts.bwclibs || {};
        bwclibs.Utils = bwclibs.Utils || config.walletUtils;

        return new CSClient(opts);
    };

    service.createNoticeBoard = NoticeBoard.create;

    service.getNoticeExtensionBackup = function (noticeBoard) {
        return new NoticeExtBackup(noticeBoard);
    };

    return service;
}]);
