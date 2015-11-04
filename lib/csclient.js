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
    self.getHash(credentials, function (err, hash) {
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


CSClient.prototype._createBackupRequestParams = function (walletId, reqId, timestamp) {
    return {
        method: 'POST',
        url: this.baseUrl + '/wallets/' + walletId + '/backup',
        data: {
            reqId: reqId,
            reqTimestamp: timestamp
        }
    };
};

/**
 * Create a new backup request
 *
 * @param credentials
 * @param { function(err, reqId) } cb
 */
CSClient.prototype.createBackupRequest = function (credentials, cb) {
    if (invalidCredentials(credentials)) return cb(new Error('incomplete credentials'));
    var walletId = credentials.walletId;
    var reqId = Math.random().toString(36).substr(2, 11);
    var getParams = this._createBackupRequestParams(walletId, reqId, Date.now());
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
                cb(null, getParams.data.reqId)
            }
        }, function errorCB(response) {
            cb(new Error(response.data));
        });
};

CSClient.prototype._deriveHX = function (backupPassword, xPrivKey) {
    var privKey = this.bwutils.Bitcore.HDPrivateKey(xPrivKey).privateKey.toString();
    var saltBits = this.sjcl.codec.hex.toBits(privKey);
    var hX = this.sjcl.misc.pbkdf2(backupPassword, saltBits, 10000, 256);
    return hX;
};
CSClient.prototype._prepareBackupPartialData = function (credentials, backupPassword, backupRequest) {
    var self = this;
    //FIXME crypto for backup
    var encXPK = self.sjcl.encrypt(backupPassword, credentials.xPrivKey, {iter: 10000});
    // use private key as salt for hX generation
    var hX = this._deriveHX(backupPassword, credentials.xPrivKey);
    var data = {
        req_data: backupRequest,
        encryptedKey: encXPK,
        hX: self.sjcl.codec.base64.fromBits(hX)
    };
    data.data_signature = self.bwutils.signMessage(JSON.stringify(data), credentials.requestPrivKey);
    var encData = self.bwutils.encryptMessage(JSON.stringify(data), credentials.sharedEncryptingKey);
    return encData;
};

/**
 * Updates pending backup request with partial data
 *
 * @param credentials
 * @param backupPassword
 * @param backupRequest
 * @param {function(err)} cb
 */
CSClient.prototype.sendBackupRequestData = function (credentials, backupPassword, backupRequest, cb) {
    var self = this;
    if (invalidCredentials(credentials) || credentials.isPrivKeyEncrypted())
        return cb(new Error('incomplete credentials'));
    if (!backupPassword) return cb(new Error('missing backup encrypting password'))
    if (!backupRequest) return cb(new Error('missing parameter backupRequest'));
    if (credentials.copayerId === backupRequest.reqCopayer)
        return cb(new Error('backup request was created by the same copayer'));
    var walletId = credentials.walletId;
    // TODO validation: backupRequest should be consistent with credentials
    var encData = self._prepareBackupPartialData(credentials, backupPassword, backupRequest);
    var getParams = {
        method: 'PATCH',
        url: self.baseUrl + '/wallets/' + walletId + '/backup',
        data: {
            reqId: backupRequest.reqId,
            partialData: encData
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
            } else if (!_.isString(data.reqId)) {
                cb(new Error('Invalid server reply: ' + data));
            } else {
                //TODO check data fields and validate request signature
                cb(null, data)
            }
        }, function errorCB(response) {
            cb(new Error(response.data));
        });
};

/**
 * Decode backup partial data and complete backup data
 *
 * @param credentials
 * @param backupRequest backup request including partial data
 * @return
 */
CSClient.prototype.buildBackupData = function (credentials, backupRequest) {
    if (!backupRequest || !backupRequest.partialData || !backupRequest.reqId ||
        !backupRequest.reqCopayer || !backupRequest.reqTimestamp || !backupRequest.reqSignature)
    {
        throw new Error('Missing or incomplete backupRequest');
    }
    if (backupRequest.reqCopayer !== credentials.copayerId)
        throw new Error('backupRequest should be created by the copayer owning credentials');
    if (credentials.n !== 3 || credentials.m != 2)
        throw new Error('Not 2 of 3 wallet');
    if (!credentials.publicKeyRing || credentials.publicKeyRing.length !== 3)
        throw new Error('publicKeyRing incomplete');
    if (!this._verifyBackupRequestSignature(backupRequest, credentials))
        throw new Error('Invalid backupRequest Signature');
    var decData = JSON.parse(this.bwutils.decryptMessage(backupRequest.partialData, credentials.sharedEncryptingKey));
    if (!decData.encryptedKey || !decData.hX || !decData.req_data || !decData.req_data.reqCopayer || !decData.req_data.reqId)
        throw new Error('Invalid partialData');
    if (decData.req_data.reqId !== backupRequest.reqId ||
        decData.req_data.reqCopayer !== backupRequest.reqCopayer ||
        decData.req_data.reqTimestamp !== backupRequest.reqTimestamp ||
        decData.req_data.reqSignature !== backupRequest.reqSignature
    ) {
        throw new Error('partialData inconsistency');
    }
    var encXPK = this.sjcl.encrypt(decData.hX, credentials.xPrivKey, {iter: 10000});

    var pubKeys = credentials.publicKeyRing
        .filter(function (xpk) {
            return xpk !== credentials.xPubKey;
        });
    var data = _.clone(decData);
    delete data.data_signature;
    var msg = JSON.stringify(data);
    var serverPubKey;
    if (this.bwutils.verifyMessage(msg, decData.data_signature, pubKeys[0].requestPubKey))
        serverPubKey = pubKeys[1].xPubKey;
    else if (this.bwutils.verifyMessage(msg, decData.data_signature, pubKeys[1].requestPubKey))
        serverPubKey = pubKeys[0].xPubKey;
    else
        throw new Error('Invalid partialData signature');

    return {
        encPrivKey1: decData.encryptedKey,
        encPrivKey2: encXPK,
        xPubKey3: serverPubKey,
    };
};

/**
 *
 * @param backupData
 * @param {string} password
 * @returns {{xPrivKey1: string, xPrivKey2: string, xPubKey3: string}} 2 extended private keys and 1 extended public key
 */
CSClient.prototype.decryptBackupData = function (backupData, password) {
    if (!backupData || !password || !backupData.encPrivKey1 || !backupData.encPrivKey2 || !backupData.xPubKey3)
        throw new Error('Missing or invalid parameters');
    var xpk1, xpk2, encXPK2;
    try {
        xpk1 = sjcl.decrypt(password, backupData.encPrivKey1);
        encXPK2 = backupData.encPrivKey2;
    } catch (err) {
        xpk1 = sjcl.decrypt(password, backupData.encPrivKey2);
        encXPK2 = backupData.encPrivKey1;
    }
    var hX = this._deriveHX(password, xpk1);
    xpk2 = sjcl.decrypt(hX, encXPK2);
    return {
        xPrivKey1: xpk1,
        xPrivKey2: xpk2,
        xPubKey3: backupData.xPubKey3
    };
};

CSClient.prototype._verifyBackupRequestSignature = function (backupRequest, credentials) {
    var params = this._createBackupRequestParams(credentials.walletId, backupRequest.reqId, backupRequest.reqTimestamp);
    var message = [params.method.toLowerCase(), params.url, JSON.stringify(params.data || {})].join('|');
    return this.bwutils.verifyMessage(message, backupRequest.reqSignature, credentials.requestPubKey);
};

/**
 * Remove backup request data from server
 *
 * @param credentials
 * @param { function(err) } cb
 */
CSClient.prototype.cleanupBackupRequest = function (credentials, cb) {
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
