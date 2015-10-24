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
    if (!opts || !opts.baseUrl || !opts.httpRequest || !opts.bwutils || !opts.sjcl)
        throw new Error('missing parameter');

    var urlobj = url.parse(opts.baseUrl);
    this.baseHost = urlobj.host;
    this.baseUrl = urlobj.href;
    this.httpRequest = opts.httpRequest;
    this.bwutils = opts.bwutils;
    this.sjcl = opts.sjcl;
}

CSClient.prototype._signRequest = function (credentials, params) {
    var message = [params.method.toLowerCase(), params.url, JSON.stringify(params.data || {})].join('|');
    var signature = this.bwutils.signMessage(message, credentials.requestPrivKey);
    params.headers = params.headers || {};
    params.headers['x-identity'] = credentials.copayerId;
    params.headers['x-signature'] = signature;
    params.headers['x-client-version'] = 'CSClient';
};

function invalidCredentials(credentials, cb) {
    return !credentials || !credentials.requestPrivKey || !credentials.copayerId ||
        !credentials.walletId || !credentials.network || !credentials.sharedEncryptingKey
}
CSClient.prototype.getHash = function (credentials, cb) {
    if (invalidCredentials(credentials)) return cb(new Error('incomplete credentials'));
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
                cb(null, response.data.copayerHash)
            } else {
                cb(new Error('Copayer hash missing: ' + response.data));
            }
        }, function errorCB(response) {
            cb(new Error('Error: ' + response.data));
        });
};

CSClient.prototype.joinWallet = function (credentials, cb) {
    if (invalidCredentials(credentials) || !credentials.walletPrivKey) return cb(new Error('incomplete credentials'));
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
    if (invalidCredentials(credentials)) return cb(new Error('incomplete credentials'));
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
    this.httpRequest(getParams)
        .then(function successCB(response) {
            //TODO full data validation
            if (_.isNumber(response.data.spendingLimit)) {
                cb(null, response.data)
            } else {
                cb(new Error('Invalid server reply: ' + response.data));
            }
        }, function errorCB(response) {
            cb(response);
        });
};

CSClient.prototype.requestSpendingLimit = function (credentials, limit, cb) {
    if (invalidCredentials(credentials)) return cb(new Error('incomplete credentials'));
    var walletId = credentials.walletId;
    var params = {
        method: 'PUT',
        url: this.baseUrl + '/wallets/' + walletId + '/spendinglimit',
        data: {'spendingLimit': limit}
    };
    this._signRequest(credentials, params);
    this.httpRequest(params)
        .then(function successCB(response) {
            if (_.isString(response.data.result)) {
                cb(null, response.data)
            } else {
                cb(new Error('Invalid server reply: ' + response.data));
            }
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
    if (invalidCredentials(credentials)) return cb(new Error('incomplete credentials'));
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
            if (_.isString(response.data.result)) {
                cb(null, response.data)
            } else {
                cb(new Error('Invalid server reply: ' + response.data));
            }
        }, function errorCB(response) {
            cb(response);
        });
};

CSClient.prototype.initNotifications = function (credentials, cb) {
    if (invalidCredentials(credentials)) return cb(new Error('incomplete credentials'));
    var self = this;

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

    socket.once('challenge', function (nonce) {
        //TODO $.checkArgument(nonce);

        var auth = {
            copayerId: credentials.copayerId,
            message: nonce,
            signature: self.bwutils.signMessage(nonce, credentials.requestPrivKey),
        };
        socket.emit('authorize', auth);
    });
};

/**
 * Create a new backup request
 *
 * @param credentials
 * @param { function(err, reqId) } cb
 */
CSClient.prototype.createBackupRequest = function (credentials, cb) {
    //TODO tests
    if (invalidCredentials(credentials)) return cb(new Error('incomplete credentials'));
    var walletId = credentials.walletId;
    var getParams = {
        method: 'POST',
        url: this.baseUrl + '/wallets/' + walletId + '/backup',
        data: {
            req_id: Math.random().toString(36).substr(2, 11),
            req_timestamp: Date.now()
        }
    };
    this._signRequest(credentials, getParams);
    this.httpRequest(getParams)
        .then(function successCB(response) {
            var data = response.data;
            if (!_.isPlainObject(data) || !_.isString(data.result)) {
                //TODO logging
                cb(new Error('Invalid server reply: ' + data));
            } else if (data.result !== 'OK') {
                cb(new Error(data.result));
            } else {
                cb(null, getParams.data.req_id)
            }
        }, function errorCB(response) {
            cb(new Error(response.data));
        });
};

/**
 * Updates pending backup request with partial data
 *
 * @param credentials
 * @param backupPassword
 * @param {function(err)} cb
 */
CSClient.prototype.setBackupRequestData = function (credentials, backupPassword, cb) {
    var self = this;
    //TODO tests
    if (invalidCredentials(credentials) || credentials.isPrivKeyEncrypted())
        return cb(new Error('incomplete credentials'));
    if (!backupPassword) return cb(new Error('missing backup encrypting password'))
    var walletId = credentials.walletId;
    self.getBackupRequest(credentials, function (err, backupRequest) {
        if (err) return cb(err);
        if (!backupRequest)
            return cb(new Error('no pending backup request'));
        if (credentials.copayerId === backupRequest.reqCopayer)
            return cb(new Error('pending backup request was created by the same copayer'));
        //FIXME crypto for backup
        var encXPK = self.sjcl.encrypt(backupPassword, credentials.xPrivKey, { iter: 10000 });
        // use xPrivKey as salt for hX generation
        var saltBits = sjcl.codec.hex.toBits(credentials.xPrivKey);
        var hX = sjcl.misc.pbkdf2(backupPassword, saltBits, 1000, 128);
        var data = {
            req_data: backupRequest,
            encryptedKey: sjcl.codec.base64.fromBits(encXPK),
            hX: sjcl.codec.base64.fromBits(hX)
        };
        data.data_signature = self.bwutils.signMessage(JSON.stringify(data), credentials.requestPrivKey);
        var encData = self.bwutils.encryptMessage(JSON.stringify(data), credentials.sharedEncryptingKey);
        var getParams = {
            method: 'PATCH',
            url: self.baseUrl + '/wallets/' + walletId + '/backup',
            data: {
                req_id: backupRequest.reqId,
                partial_data: encData
            }
        };
        self._signRequest(credentials, getParams);
        self.httpRequest(getParams)
            .then(function successCB(response) {
                var data = response.data;
                if (!_.isPlainObject(data) || !_.isString(data.result)) {
                    //TODO logging
                    cb(new Error('Invalid server reply: ' + data));
                } else if (data.result !== 'OK') {
                    cb(new Error(data.result));
                } else {
                    cb()
                }
            }, function errorCB(response) {
                cb(new Error(response.data));
            });
    });
};

/**
 * Retrieve current backup request data
 *
 * @param credentials
 * @param { function(err, backupRequest) } cb
 */
CSClient.prototype.getBackupRequest = function (credentials, cb) {
    //TODO tests
    if (invalidCredentials(credentials)) return cb(new Error('incomplete credentials'));
    var walletId = credentials.walletId;
    var getParams = {
        method: 'GET',
        url: this.baseUrl + '/wallets/' + walletId + '/backup',
    };
    this._signRequest(credentials, getParams);
    this.httpRequest(getParams)
        .then(function successCB(response) {
            var data = response.data;
            if (!_.isPlainObject(data)) {
                //TODO logging
                cb(new Error('Invalid server reply: ' + data));
            } else if (_.isEmpty(data)) {
                cb(null, null);
            } else if (!_.isString(data.req_id)) {
                cb(new Error('Invalid server reply: ' + data));
            } else {
                //TODO check data fields and validate data.partial_data if it is present
                cb(null, data)
            }
        }, function errorCB(response) {
            cb(new Error(response.data));
        });
};

/**
 * Remove backup request data from server
 *
 * @param credentials
 * @param { function(err) } cb
 */
CSClient.prototype.cleanupBackupRequest = function (credentials, cb) {
    //TODO tests
    if (invalidCredentials(credentials)) return cb(new Error('incomplete credentials'));
    var walletId = credentials.walletId;
    var getParams = {
        method: 'DELETE',
        url: this.baseUrl + '/wallets/' + walletId + '/backup',
    };
    this._signRequest(credentials, getParams);
    this.httpRequest(getParams)
        .then(function successCB(response) {
            var data = response.data;
            if (!_.isPlainObject(data) || !_.isString(data.result)) {
                //TODO logging
                cb(new Error('Invalid server reply: ' + data));
            } else if (data.result !== 'OK') {
                cb(new Error(data.result));
            } else {
                cb()
            }
        }, function errorCB(response) {
            cb(new Error(response.data));
        });
};

module.exports = CSClient;
