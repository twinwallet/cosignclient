'use strict';

var _ = require('lodash');
//var $ = require('preconditions').singleton();
var url = require('url');
var io = require('socket.io-client');

/**
 *
 * @param opts
 * @constructor
 */
function CSClient(opts) {
    //TODO check requirements
    opts = opts || {};

    var urlobj = url.parse(opts.baseUrl);
    this.baseHost = urlobj.host;
    this.baseUrl = urlobj.href;
    this.httpRequest = opts.httpRequest;
    this.bwutils = opts.bwutils;
}

CSClient.prototype._signRequest = function (credentials, params) {
    var message = [params.method.toLowerCase(), params.url, JSON.stringify(params.data || {})].join('|');
    var signature = this.bwutils.signMessage(message, credentials.requestPrivKey);
    params.headers = params.headers || {};
    params.headers['x-identity'] = credentials.copayerId;
    params.headers['x-signature'] = signature;
    params.headers['x-client-version'] = 'CSClient';
};

CSClient.prototype.getHash = function (credentials, cb) {
    var self = this;
    var params = {
        method: 'POST',
        url: self.baseUrl + '/wallets/' + credentials.walletId + '/setup',
        data: {
            network: credentials.network
        }
    };
    self._signRequest(credentials, params);

    self.httpRequest(params)
        .then(function (response) {
            if (!!response.data.copayerHash) {
                //TODO returned data validation
                cb(null, data.copayerHash)
            } else {
                cb(new Error('Copayer hash missing: ' + response.data));
            }
        }, function errorCB(response) {
            cb(new Error('Error: ' + response.data));
        });
};

CSClient.prototype.joinWallet = function (credentials, cb) {
    var self = this;
    //TODO controllare se manca solo il server al join
    var walletId = credentials.walletId;
    var network = credentials.network;
    self.getHash(walletId, network, function (err, hash) {
        if (err) return cb(err);
        var signature = self.bwutils.signMessage(hash, credentials.walletPrivKey);
        var walletPubKey = self.bwutils.Bitcore.PrivateKey.fromString(credentials.walletPrivKey).toPublicKey().toString();
        var data = {
            copayerHashSignature: signature,
            walletPubKey: walletPubKey,
            sharedEncryptingKey: credentials.sharedEncryptingKey
        };
        var params = {
            method: 'POST',
            url: self.baseUrl + '/wallets/' + walletId,
            data: data
        };
        self._signRequest(credentials, params);
        self.httpRequest(params)
            .then(function successCB(response) {
                //TODO ok
                console.log('join ok');
                cb(null, response.data);
            }, function errorCB(response) {
                //TODO error
                console.error(response);
                cb(new Error(response));
            });
    });
};

CSClient.prototype.getSpendingLimit = function (credentials, cb) {
    var walletId = credentials.walletId;
    var getParams = {
        method: 'GET',
        url: this.baseUrl + '/wallets/' + walletId + '/spendinglimit',
        //headers: {
        //'cache-control': 'no-cache',
        //'accept-language': undefined,
        //Accept: 'application/json',
        //'If-None-Match': undefined,
        //    'Authorization': authHeader,
        //},
        //transformResponse: [function(value) { return value; }],
        //transformRequest: [function(value) { return value; }],
    };
    this._signRequest(credentials, getParams);
    self.httpRequest(getParams)
        .then(function successCB(response) {
            cb(null, response.data);
        }, function errorCB(response) {
            cb(response);
        });
};

CSClient.prototype.requestSpendingLimit = function (credentials, limit, cb) {
    var walletId = credentials.walletId;
    var params = {
        method: 'PUT',
        url: this.baseUrl + '/wallets/' + walletId + '/spendinglimit',
        data: {'spendingLimit': limit}
    };
    this._signRequest(credentials, params);
    this.httpRequest(params)
        .then(function successCB(response) {
            cb(null, response.data);
        }, function errorCB(response) {
            cb(response);
        });
};

/**
 *
 * @param {boolean} confirm
 * @param cb
 */
CSClient.prototype.confirmSpendingLimit = function (credentials, limit, confirm, cb) {
    var walletId = credentials.walletId;
    var params = {
        method: 'PATCH',
        url: this.baseUrl + '/wallets/' + walletId + '/spendinglimit',
        data: {
            spendingLimit: limit,
            status: confirm ? 'confirm' : 'reject'
        }
    };
    this._signRequest(credentials, params);
    this.httpRequest(params)
        .then(function successCB(response) {
            var result = response.data.result;
            if (result === 'invalid') {
                cb(new Error('Invalid request'));
            } else {
                cb(null);
            }
        }, function errorCB(response) {
            cb(response);
        });
};

CSClient.prototype.initNotifications = function (credentials, cb) {
    var self = this;

    var walletId = credentials.walletId;
    if (!walletId) return cb(new Error('Invalid credentials'));

    var socket = io.connect('http://' + self.baseHost, {
        'force new connection': true,
        'reconnection': true,
        'reconnectionDelay': 5000,
        'secure': true,
        //'transports': self.transports,
    });

    socket.once('unauthorized', function () {
        return cb(new Error('Could not establish web-sockets connection: Unauthorized'));
    });

    socket.once('authorized', function () {
        return cb(null, socket);
    });

    //socket.on('notification', function (data) {
    //    if (data.walletId === walletId) {
    //        var ev = 'notificationXT/' + data.type;
    //        $rootScope.$emit(ev, data);
    //    } else {
    //        // TODO
    //    }
    //});
    //
    //socket.on('reconnecting', function () {
    //    //self.emit('reconnecting');
    //});
    //
    //socket.on('reconnect', function () {
    //    //self.emit('reconnect');
    //});

    socket.once('challenge', function (nonce) {
        //TODO $.checkArgument(nonce);

        var auth = {
            copayerId: credentials.copayerId,
            message: nonce,
            signature: profileService.getUtils().signMessage(nonce, credentials.requestPrivKey),
        };
        socket.emit('authorize', auth);
    });
};

CSClient.prototype.getBackupRequest = function (cb) {
    //TODO getBackupRequest
    var data = null;
    return cb(null, data);
};

CSClient.prototype.newBackupRequest = function (cb) {
    //TODO newBackupRequest
    var data = null;
    return cb(null, data);
};

CSClient.prototype.getBackupStatus = function (cb) {
    //TODO getBackupRequest
    var data = null;
    return cb(null, data);
};

module.exports = CSClient;
