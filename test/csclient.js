'use strict';

var _ = require('lodash');
var sinon = require('sinon');
var chai = require('chai');
var should = chai.should();
var expect = chai.expect;
var chaiSubset = require('chai-subset');
chai.use(chaiSubset);
var bwclient = require('bitcore-wallet-client');
var Credentials = require('bitcore-wallet-client/lib/credentials');
var walletUtils = bwclient.Utils;
var Bitcore = walletUtils.Bitcore;
var sjcl = bwclient.sjcl;
var io = require('socket.io-client');
var CSClient = require('../lib/csclient');

// request key is the derivation m/1'/0 of tprv8ZgxMBicQKsPfB68j6QH2jhxju935kx7eXqg28aMBD49wd7Crrqwv665r7ikjeMH8N1jb25J45LhTm7FwhqNRHp7Ddy6CcVfYpHW73zAdvP
var MOCK_REQPRIVKEY = '2fde5d887c7c60c723d46947706b747a84a019e3863bb00a8ad2127f4ec09273';
var MOCK_REQPUBKEY = (new Bitcore.PrivateKey(MOCK_REQPRIVKEY)).toPublicKey().toString();
var MOCK_WALLETPRIVKEY = 'f57ff6cb88b8b7777250828017de1dd69ee29ad56eeb492929ef522e0cc17cea';
var MOCK_WALLETPUBKEY = (new Bitcore.PrivateKey(MOCK_WALLETPRIVKEY)).toPublicKey().toString();
var MOCK_REQUEST_NULL = function() { return { then: function(s,e) {} } };
var MOCK_SHAREDENCRIPTINGKEY = '-shared-encripting-key-placeholder-';
var MOCK_COPAYERHASH = '-copayer-hash-placeholder-';
var MOCK_CREDENTIALS = {
    walletId: '7c9a7df9-990c-4de6-8f49-572ff0938216',
    sharedEncryptingKey: MOCK_SHAREDENCRIPTINGKEY,
    copayerId: '2a59dd2a92ef6108b46e277ee5aa9778d00b1092f171601f466551cdc7d90668',
    requestPrivKey: MOCK_REQPRIVKEY,
    network: Bitcore.Networks.livenet,
};

var MOCK_CREDENTIALS2 = Credentials.fromExtendedPrivateKey('tprv8ZgxMBicQKsPfB68j6QH2jhxju935kx7eXqg28aMBD49wd7Crrqwv665r7ikjeMH8N1jb25J45LhTm7FwhqNRHp7Ddy6CcVfYpHW73zAdvP');
MOCK_CREDENTIALS2.addWalletInfo(
    '7c9a7df9-990c-4de6-8f49-572ff0938216',
    '--wallet-name--',
    2,
    3,
    MOCK_WALLETPRIVKEY,
    '--copayer-name--'
);

function successHttpHelper(response) {
    return {
        then: function (successCallback, errorCallback) {
            process.nextTick(function() {
                successCallback(response);
            });
        }
    }
}

function errorHttpHelper(response) {
    return {
        then: function (successCallback, errorCallback) {
            process.nextTick(function () {
                errorCallback(response);
            });
        }
    }
}

function signatureShouldBeOk(callArg, expected, expectedPubKey) {
    var msg = expected.method.toLocaleLowerCase() + '|' + expected.url + '|' + JSON.stringify(expected.data || {});
    var signOk = walletUtils.verifyMessage(msg, callArg.headers['x-signature'], expectedPubKey);
    signOk.should.be.true;
}

describe('CSClient', function () {
    var MOCK_OPTS = {
        baseUrl: 'http://localhost:1234/cosign',
        httpRequest: MOCK_REQUEST_NULL,
        bwutils: walletUtils,
        sjcl: sjcl
    };
    var creation_opts;
    var MOCK_HTTP_RESPONSE = {
        data: {},
        status: 200,
        //statusText: 'OK',
        config: {headers: {}, method: '', url: ''},
        headers: null,
    };
    var http_response;

    beforeEach(function () {
        creation_opts = _.clone(MOCK_OPTS);
        http_response = _.clone(MOCK_HTTP_RESPONSE);
    });

    /**
     * Usage example:
     * testReturnedError(done, function(csclient, callback) {
     *    csclient.getHash(null, callback);
     * });
     * @param done
     * @param {function(csclient, callback)} cb
     */
    function testReturnedError(done, cb) {
        var csclient = new CSClient(creation_opts);
        cb(csclient, function (err, data) {
            should.exist(err);
            should.not.exist(data);
            done();
        });
    }

    /**
     * @param {Credentials} completeCredentials
     * @param {function(csclient, credentials, callback)} cb
     */
    function it_testsIncompleteCredentials(completeCredentials, cb) {
        _.forEach(completeCredentials, function (v, f_name) {
            it('should return error with missing credential field ' + f_name, function (done) {
                var csclient = new CSClient(creation_opts);
                var credentials = _.clone(completeCredentials);
                delete credentials[f_name];
                cb(csclient, credentials, function (err, data) {
                    should.exist(err);
                    should.not.exist(data);
                    done();
                });
            });
        });
    }

    function testTerminationWithoutError(httpResponseData, done, cb) {
        http_response.data = _.clone(httpResponseData);
        creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
        var csclient = new CSClient(creation_opts);
        cb(csclient, function (err, hash) {
            should.not.exist(err);
            done();
        });
    }

    function testHttpRequestCall(exp_method, exp_url, exp_data, exp_credentials, done, cb) {
        var expected = {
            headers: {
                'x-client-version': 'CSClient',
                'x-identity': exp_credentials.copayerId,
            },
            method: exp_method,
            url: exp_url,
            data: exp_data
        };
        http_response.data = _.clone(MOCK_HTTP_RESPONSE);
        var reqStub = creation_opts.httpRequest = sinon.expectation.create()
            .once()
            .returns(successHttpHelper(http_response));
        var csclient = new CSClient(creation_opts);
        cb(csclient, function(err, data) {
            reqStub.verify();
            var callArg = reqStub.getCall(0).args[0];
            callArg.should.containSubset(expected);
            if (typeof exp_data === 'undefined')
                should.not.exist(callArg.data);
            var reqPubKey = (new Bitcore.PrivateKey(exp_credentials.requestPrivKey)).toPublicKey().toString();
            signatureShouldBeOk(callArg, expected, reqPubKey);
            done();
        });
    }

    function testRetunedData(httpResponseData, expectedReturnedData, done, cb) {
        http_response.data = _.clone(httpResponseData);
        creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
        var csclient = new CSClient(creation_opts);
        cb(csclient, function (err, data) {
            should.exist(data);
            data.should.deep.equal(expectedReturnedData);
            done();
        });
    }

    function testBadHttpResponse(done, cb) {
        http_response.data = 'error';
        creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
        testReturnedError(done, cb);
    }

    function testHttpError(done, cb) {
        http_response.data = null;
        http_response.status = 500;
        creation_opts.httpRequest = sinon.stub().returns(errorHttpHelper(http_response));
        testReturnedError(done, cb);
    }

    describe('constructor', function () {
        it('should throw error with null opts', function () {
            expect(function () {
                var csclient = new CSClient(null);
            }).to.throw(Error);
        });
        _.forEach(MOCK_OPTS, function (v, parameter) {
            it('should throw error with missing parameter ' + parameter, function () {
                delete creation_opts[parameter];
                expect(function () {
                    var csclient = new CSClient(creation_opts);
                }).to.throw(Error);
            });
        });
        it('should set properties', function () {
            var csclient = new CSClient(creation_opts);
            csclient.baseUrl.should.equal('http://localhost:1234/cosign');
            csclient.baseHost.should.equal('localhost:1234');
            csclient.httpRequest.should.equal(MOCK_OPTS.httpRequest);
            csclient.bwutils.should.equal(MOCK_OPTS.bwutils);
        });
    });

    describe('.getHash', function () {
        it('should return error with null argument', function (done) {
            testReturnedError(done, function (csclient, callback) {
                csclient.getHash(null, callback);
            });
        });
        it_testsIncompleteCredentials(MOCK_CREDENTIALS, function(csclient, credentials, callback) {
            csclient.getHash(credentials, callback);
        });
        it('should terminate', function (done) {
            testTerminationWithoutError({copayerHash: MOCK_COPAYERHASH}, done, function(csclient, callback) {
                csclient.getHash(MOCK_CREDENTIALS, callback);
            });
        });
        it('should call httpRequest with correct params', function (done) {
            var url = MOCK_OPTS.baseUrl + '/wallets/' + MOCK_CREDENTIALS.walletId + '/setup';
            var exp_data = {network: MOCK_CREDENTIALS.network};
            testHttpRequestCall('POST', url, exp_data, MOCK_CREDENTIALS, done, function(csclient, callback) {
                csclient.getHash(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return correct hash', function (done) {
            testRetunedData({copayerHash: MOCK_COPAYERHASH}, MOCK_COPAYERHASH, done, function(csclient, callback) {
                csclient.getHash(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return error if bad response', function (done) {
            testBadHttpResponse(done, function(csclient, callback) {
                csclient.getHash(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return error "Copayer hash missing"', function (done) {
            http_response.data = {};
            creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
            var csclient = new CSClient(creation_opts);
            csclient.getHash(MOCK_CREDENTIALS, function (err, hash) {
                should.exist(err);
                _.startsWith(err.message, 'Copayer hash missing').should.be.true;
                should.not.exist(hash);
                done();
            });
        });
        it('should return error', function (done) {
            testHttpError(done, function(csclient, callback) {
                csclient.getHash(MOCK_CREDENTIALS, callback);
            });
        });
    });

    describe('.joinWallet', function () {
        var MOCK_CREDENTIALS2 = _.clone(MOCK_CREDENTIALS);
        MOCK_CREDENTIALS2.walletPrivKey = MOCK_WALLETPRIVKEY;

        it('should return error with null argument', function (done) {
            testReturnedError(done, function (csclient, callback) {
                csclient.joinWallet(null, callback);
            });
        });
        it_testsIncompleteCredentials(MOCK_CREDENTIALS2, function(csclient, credentials, callback) {
            csclient.joinWallet(credentials, callback);
        });
        it('should return error on getHash() error', function (done) {
            creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
            var csclient = new CSClient(creation_opts);
            sinon.stub(csclient, 'getHash').yields(new Error());
            csclient.joinWallet(MOCK_CREDENTIALS2, function (err, data) {
                should.exist(err);
                should.not.exist(data);
                done();
            });
        });
        it('should call httpRequest with correct params', function (done) {
            var url = MOCK_OPTS.baseUrl + '/wallets/' + MOCK_CREDENTIALS2.walletId
            var exp_data = {
                copayerHashSignature: '3045022100fe22b54f14c41a0b37d99526f7c0e0dd1f260859dc6d8ab0406ec66a66e4c9b3022002f3553c55d6938507cc40372152c28f2284b472339051963781ebc91692a2e3',
                walletPubKey: MOCK_WALLETPUBKEY,
                sharedEncryptingKey: MOCK_CREDENTIALS2.sharedEncryptingKey
            };
            testHttpRequestCall('POST', url, exp_data, MOCK_CREDENTIALS2, done, function(csclient, callback) {
                sinon.stub(csclient, 'getHash').yields(null, MOCK_COPAYERHASH);
                csclient.joinWallet(MOCK_CREDENTIALS2, callback);
            });
        });
        it('should complete successfully', function (done) {
            testRetunedData({}, {}, done, function(csclient, callback) {
                sinon.stub(csclient, 'getHash').yields(null, MOCK_COPAYERHASH);
                csclient.joinWallet(MOCK_CREDENTIALS2, callback);
            });
        });
        it('should return error if http error', function (done) {
            testHttpError(done, function(csclient, callback) {
                sinon.stub(csclient, 'getHash').yields(null, MOCK_COPAYERHASH);
                csclient.joinWallet(MOCK_CREDENTIALS, callback);
            });
        });
    });

    describe('.getSpendingLimit', function () {
        var MOCK_HTTP_RESPONSE = {spendingLimit: 1000, consumed: 222, pendingLimit: 2000, pendingLimitApproved: false};

        it('should return error with null argument', function (done) {
            testReturnedError(done, function (csclient, callback) {
                csclient.getSpendingLimit(null, callback);
            });
        });
        it_testsIncompleteCredentials(MOCK_CREDENTIALS,  function(csclient, credentials, callback) {
            csclient.getSpendingLimit(credentials, callback);
        });
        it('should terminate without error', function (done) {
            testTerminationWithoutError(MOCK_HTTP_RESPONSE, done, function(csclient, callback) {
                csclient.getSpendingLimit(MOCK_CREDENTIALS, callback);
            });
        });
        it('should call httpRequest with correct params', function (done) {
            var url = MOCK_OPTS.baseUrl + '/wallets/' + MOCK_CREDENTIALS.walletId + '/spendinglimit'
            testHttpRequestCall('GET', url, undefined, MOCK_CREDENTIALS, done, function(csclient, callback) {
                csclient.getSpendingLimit(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return correct data', function (done) {
            testRetunedData(MOCK_HTTP_RESPONSE, MOCK_HTTP_RESPONSE, done, function(csclient, callback) {
                csclient.getSpendingLimit(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return error if bad response', function (done) {
            testBadHttpResponse(done, function(csclient, callback) {
                csclient.getSpendingLimit(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return error', function (done) {
            testHttpError(done, function(csclient, callback) {
                csclient.getSpendingLimit(MOCK_CREDENTIALS, callback);
            });
        });
    });

    describe('.requestSpendingLimit', function () {
        var MOCK_HTTP_RESPONSE = {result: 'OK'};

        it('should return error with null argument', function (done) {
            testReturnedError(done, function (csclient, callback) {
                csclient.requestSpendingLimit(null, 100, callback);
            });
        });
        it_testsIncompleteCredentials(MOCK_CREDENTIALS,  function(csclient, credentials, callback) {
            csclient.requestSpendingLimit(credentials, 100, callback);
        });
        it('should terminate without error', function (done) {
            testTerminationWithoutError(MOCK_HTTP_RESPONSE, done, function(csclient, callback) {
                csclient.requestSpendingLimit(MOCK_CREDENTIALS, 100, callback);
            });
        });
        it('should call httpRequest with correct params', function (done) {
            var url = MOCK_OPTS.baseUrl + '/wallets/' + MOCK_CREDENTIALS.walletId + '/spendinglimit'
            testHttpRequestCall('PUT', url, {spendingLimit: 100}, MOCK_CREDENTIALS, done, function(csclient, callback) {
                csclient.requestSpendingLimit(MOCK_CREDENTIALS, 100, callback);
            });
        });
        it('should return correct data', function (done) {
            testRetunedData(MOCK_HTTP_RESPONSE, MOCK_HTTP_RESPONSE, done, function(csclient, callback) {
                csclient.requestSpendingLimit(MOCK_CREDENTIALS, 100, callback);
            });
        });
        it('should return error if bad response', function (done) {
            testBadHttpResponse(done, function(csclient, callback) {
                csclient.requestSpendingLimit(MOCK_CREDENTIALS, 100, callback);
            });
        });
        it('should return error', function (done) {
            testHttpError(done, function(csclient, callback) {
                csclient.requestSpendingLimit(MOCK_CREDENTIALS, 100, callback);
            });
        });
    });

    describe('.confirmSpendingLimit', function () {
        var MOCK_HTTP_RESPONSE = {result: 'OK'};

        it('should return error with null argument', function (done) {
            testReturnedError(done, function (csclient, callback) {
                csclient.confirmSpendingLimit(null, 100, true, callback);
            });
        });
        it_testsIncompleteCredentials(MOCK_CREDENTIALS,  function(csclient, credentials, callback) {
            csclient.confirmSpendingLimit(credentials, 100, true, callback);
        });
        it('should terminate without error', function (done) {
            testTerminationWithoutError(MOCK_HTTP_RESPONSE, done, function(csclient, callback) {
                csclient.confirmSpendingLimit(MOCK_CREDENTIALS, 100, true, callback);
            });
        });
        it('should call httpRequest with correct params', function (done) {
            var url = MOCK_OPTS.baseUrl + '/wallets/' + MOCK_CREDENTIALS.walletId + '/spendinglimit'
            var exp_data = {
                spendingLimit: 100,
                status: 'confirm'
            };
            testHttpRequestCall('PATCH', url, exp_data, MOCK_CREDENTIALS, done, function(csclient, callback) {
                csclient.confirmSpendingLimit(MOCK_CREDENTIALS, 100, true, callback);
            });
        });
        it('should return correct data', function (done) {
            testRetunedData(MOCK_HTTP_RESPONSE, MOCK_HTTP_RESPONSE, done, function(csclient, callback) {
                csclient.confirmSpendingLimit(MOCK_CREDENTIALS, 100, true, callback);
            });
        });
        it('should return error if bad response', function (done) {
            testBadHttpResponse(done, function(csclient, callback) {
                csclient.confirmSpendingLimit(MOCK_CREDENTIALS, 100, true, callback);
            });
        });
        it('should return error', function (done) {
            testHttpError(done, function(csclient, callback) {
                csclient.confirmSpendingLimit(MOCK_CREDENTIALS, 100, true, callback);
            });
        });
    });

    describe('.initNotifications', function () {
        var socket = {
            once: sinon.spy(),
            emit: sinon.spy()
        };
        describe('basic', function () {
            it('should return error with null argument', function (done) {
                testReturnedError(done, function (csclient, callback) {
                    csclient.initNotifications(null, callback);
                });
            });
            it_testsIncompleteCredentials(MOCK_CREDENTIALS, function (csclient, credentials, callback) {
                csclient.initNotifications(credentials, callback);
            });
            it('should open socket', function () {
                var mock = sinon.mock(io);
                mock.expects('connect')
                    .once()
                    .withExactArgs(
                        'http://localhost:1234',
                        {
                            'force new connection': true,
                            'reconnection': true,
                            'reconnectionDelay': 5000,
                            'secure': true,
                        })
                    .returns(socket);
                var csclient = new CSClient(creation_opts);
                csclient.initNotifications(MOCK_CREDENTIALS, sinon.spy());
                mock.verify();
            });
        });
        describe('protocol implementation', function() {
            var csclient;
            var connectStub;
            before(function () {
                connectStub = sinon.stub(io, 'connect').returns(socket);
            });
            after(function () {
                connectStub.restore();
            });
            beforeEach(function() {
                socket.once = sinon.spy();
                socket.emit = sinon.spy();
                csclient = new CSClient(creation_opts);
            });
            var events = ['authorized', 'unauthorized', 'challenge'];
            events.forEach(function (event) {
                it('should listen "' + event + '" event', function () {
                    csclient.initNotifications(MOCK_CREDENTIALS, sinon.spy());
                    expect(socket.once.withArgs(event).calledOnce);
                });
            });
            it('should emit "authorize" event', function(done) {
                socket.once = sinon.stub();
                socket.once.withArgs('challenge').yieldsAsync('8adc3675-ca8a-4709-bdd2-b41bd8e4e879');
                socket.emit = function(event, data) {
                    event.should.equals('authorize');
                    data.should.deep.equals({
                        copayerId: MOCK_CREDENTIALS.copayerId,
                        message: '8adc3675-ca8a-4709-bdd2-b41bd8e4e879',
                        signature: '304402202049439cfc9559fba57e5be916679c6e8a3b4f825bd14ec288e4f02d7af4faa402204893a083a3ab416afe8ba63c96905dccb3e334e86965510761c81c1a9b0ec1ea'
                    });
                    done();
                };
                csclient.initNotifications(MOCK_CREDENTIALS, sinon.spy());
            });
            it('should return error on "unauthorized" event', function (done) {
                socket.once = sinon.stub();
                socket.once.withArgs('challenge').yieldsAsync('8adc3675-ca8a-4709-bdd2-b41bd8e4e879');
                socket.emit = function (event, data) {
                    process.nextTick(function () {
                        socket.once.withArgs('unauthorized').yield();
                    });
                };
                csclient.initNotifications(MOCK_CREDENTIALS, function (err, socket) {
                    should.exist(err);
                    should.not.exist(socket);
                    done();
                });

            });
            it('should return socket on "authorized" event', function (done) {
                socket.once = sinon.stub();
                socket.once.withArgs('challenge').yieldsAsync('8adc3675-ca8a-4709-bdd2-b41bd8e4e879');
                socket.emit = function (event, data) {
                    process.nextTick(function () {
                        socket.once.withArgs('authorized').yield();
                    });
                };
                csclient.initNotifications(MOCK_CREDENTIALS, function (err, socket) {
                    should.not.exist(err);
                    should.exist(socket);
                    socket.should.equal(socket);
                    done();
                });
            });
        });
    });

    describe('.createBackupRequest', function () {
        var MOCK_HTTP_RESPONSE = {
            result: 'OK'
        };

        it('should return error with null argument', function (done) {
            testReturnedError(done, function (csclient, callback) {
                csclient.createBackupRequest(null, callback);
            });
        });
        it_testsIncompleteCredentials(MOCK_CREDENTIALS,  function(csclient, credentials, callback) {
            csclient.createBackupRequest(credentials, callback);
        });
        it('should terminate without error', function (done) {
            testTerminationWithoutError(MOCK_HTTP_RESPONSE, done, function(csclient, callback) {
                csclient.createBackupRequest(MOCK_CREDENTIALS, callback);
            });
        });
        it('should call httpRequest with correct params', function (done) {
            var url = MOCK_OPTS.baseUrl + '/wallets/' + MOCK_CREDENTIALS.walletId + '/backup';
            var exp_data = {};
            var startTime = Date.now();
            testHttpRequestCall('POST', url, exp_data, MOCK_CREDENTIALS, done, function(csclient, callback) {
                csclient.createBackupRequest(MOCK_CREDENTIALS, function(err, reqId) {
                    var callArg = creation_opts.httpRequest.getCall(0).args[0];
                    callArg.data.reqId.should.be.a('string');
                    callArg.data.reqTimestamp.should.be.within(startTime, Date.now());
                    // update exp_data for signature validation
                    exp_data.reqId = callArg.data.reqId;
                    exp_data.reqTimestamp = callArg.data.reqTimestamp;
                    callback(err, reqId);
                });
            });
        });
        it('should return request id', function (done) {
            http_response.data = MOCK_HTTP_RESPONSE;
            creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
            var csclient = new CSClient(creation_opts);
            csclient.createBackupRequest(MOCK_CREDENTIALS, function (err, data) {
                should.exist(data);
                data.should.be.a('string');
                data.should.equal(creation_opts.httpRequest.getCall(0).args[0].data.reqId);
                done();
            });
        });
        it('should return error if bad response', function (done) {
            testBadHttpResponse(done, function(csclient, callback) {
                csclient.createBackupRequest(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return error if result is not OK', function (done) {
            http_response.data = {
                result: 'backup in progress'
            };
            creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
            testReturnedError(done, function (csclient, callback) {
                csclient.createBackupRequest(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return error if http error', function (done) {
            testHttpError(done, function(csclient, callback) {
                csclient.createBackupRequest(MOCK_CREDENTIALS, callback);
            });
        });
    });

    describe('.cleanupBackupRequest', function () {
        var MOCK_HTTP_RESPONSE = {
            result: 'OK'
        };

        it('should return error with null argument', function (done) {
            testReturnedError(done, function (csclient, callback) {
                csclient.cleanupBackupRequest(null, callback);
            });
        });
        it_testsIncompleteCredentials(MOCK_CREDENTIALS,  function(csclient, credentials, callback) {
            csclient.cleanupBackupRequest(credentials, callback);
        });
        it('should terminate without error', function (done) {
            testTerminationWithoutError(MOCK_HTTP_RESPONSE, done, function(csclient, callback) {
                csclient.cleanupBackupRequest(MOCK_CREDENTIALS, callback);
            });
        });
        it('should call httpRequest with correct params', function (done) {
            var url = MOCK_OPTS.baseUrl + '/wallets/' + MOCK_CREDENTIALS.walletId + '/backup';
            testHttpRequestCall('DELETE', url, undefined, MOCK_CREDENTIALS, done, function(csclient, callback) {
                csclient.cleanupBackupRequest(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return error if bad response', function (done) {
            testBadHttpResponse(done, function(csclient, callback) {
                csclient.cleanupBackupRequest(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return error if result is not OK', function (done) {
            http_response.data = {
                result: 'no backup'
            };
            creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
            testReturnedError(done, function (csclient, callback) {
                csclient.cleanupBackupRequest(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return error if http error', function (done) {
            testHttpError(done, function(csclient, callback) {
                csclient.cleanupBackupRequest(MOCK_CREDENTIALS, callback);
            });
        });
    });

    describe('.setBackupRequestData', function () {
        var MOCK_PASSWORD = 'Passw0rd';
        var MOCK_HTTP_RESPONSE = {
            result: 'OK'
        };
        var MOCK_BACKUPREQUEST = {
            reqId: '--id-placeholder--',
            reqCopayer: MOCK_COPAYERHASH,
            reqTimestamp: 1111111,
            reqSignature: '--signature-placeholder--',
        };

        it('should return error with null argument', function (done) {
            testReturnedError(done, function (csclient, callback) {
                csclient.setBackupRequestData(null, MOCK_PASSWORD, callback);
            });
        });
        it_testsIncompleteCredentials(MOCK_CREDENTIALS,  function(csclient, credentials, callback) {
            csclient.setBackupRequestData(credentials, MOCK_PASSWORD, callback);
        });
        it('should return error with encrypted credentials', function (done) {
            testReturnedError(done, function (csclient, callback) {
                var credentials = Credentials.fromObj(MOCK_CREDENTIALS2);
                credentials.setPrivateKeyEncryption('testPassw0rd');
                credentials.lock();
                csclient.setBackupRequestData(credentials, MOCK_PASSWORD, callback);
            });
        });
        it('should call getBackupRequest', function (done) {
            creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
            var csclient = new CSClient(creation_opts);
            var mock = sinon.mock(csclient).expects('getBackupRequest')
                .once()
                .withArgs(MOCK_CREDENTIALS2).
                yields(null, MOCK_BACKUPREQUEST);
            csclient.setBackupRequestData(MOCK_CREDENTIALS2, MOCK_PASSWORD, function (err, data) {
                mock.verify();
                done();
            });
        });
        it('should return error on getBackupRequest error', function (done) {
            testReturnedError(done, function (csclient, callback) {
                sinon.stub(csclient, 'getBackupRequest').yields(new Error());
                csclient.setBackupRequestData(MOCK_CREDENTIALS2, MOCK_PASSWORD, callback);
            });
        });
        it('should return error if no pending backup request', function (done) {
            testReturnedError(done, function (csclient, callback) {
                sinon.stub(csclient, 'getBackupRequest').yields(null, null);
                csclient.setBackupRequestData(MOCK_CREDENTIALS2, MOCK_PASSWORD, callback);
            });
        });
        it('should return error if pending backup request was created from same copayer', function (done) {
            testReturnedError(done, function (csclient, callback) {
                sinon.stub(csclient, 'getBackupRequest').yields(null, MOCK_BACKUPREQUEST);
                var credentials = Credentials.fromObj(MOCK_CREDENTIALS2);
                credentials.copayerId = MOCK_BACKUPREQUEST.req_copayer;
                csclient.setBackupRequestData(credentials, MOCK_PASSWORD, callback);
            });
        });
        it('should terminate without error', function (done) {
            testTerminationWithoutError(MOCK_HTTP_RESPONSE, done, function(csclient, callback) {
                sinon.stub(csclient, 'getBackupRequest').yields(null, MOCK_BACKUPREQUEST);
                csclient.setBackupRequestData(MOCK_CREDENTIALS2, MOCK_PASSWORD, callback);
            });
        });
        it('should call httpRequest with correct params', function (done) {
            var url = MOCK_OPTS.baseUrl + '/wallets/' + MOCK_CREDENTIALS2.walletId + '/backup';
            var data = {
                reqId: MOCK_BACKUPREQUEST.reqId,
                partialData: '--partila-data-placeholder--'
            };
            testHttpRequestCall('PATCH', url, data, MOCK_CREDENTIALS2, done, function(csclient, callback) {
                sinon.stub(csclient, 'getBackupRequest').yields(null, MOCK_BACKUPREQUEST);
                sinon.stub(csclient, '_prepareBackupPartialData').returns(data.partialData);
                csclient.setBackupRequestData(MOCK_CREDENTIALS2, MOCK_PASSWORD, callback);
            });
        });
        it('should return error if bad http response', function (done) {
            testBadHttpResponse(done, function(csclient, callback) {
                sinon.stub(csclient, 'getBackupRequest').yields(null, MOCK_BACKUPREQUEST);
                csclient.setBackupRequestData(MOCK_CREDENTIALS2, MOCK_PASSWORD, callback);
            });
        });
        it('should return error if result is not OK', function (done) {
            http_response.data = {
                result: 'no backup'
            };
            creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
            testReturnedError(done, function (csclient, callback) {
                csclient.setBackupRequestData(MOCK_CREDENTIALS2, MOCK_PASSWORD, callback);
            });
        });
        it('should return error if http error', function (done) {
            testHttpError(done, function(csclient, callback) {
                csclient.setBackupRequestData(MOCK_CREDENTIALS2, MOCK_PASSWORD, callback);
            });
        });
    });

    describe('.getBackupRequest', function () {
        var MOCK_HTTP_RESPONSE = {
            reqId: '--id-placeholder--',
            reqCopayer: MOCK_COPAYERHASH,
            reqTimestamp: 1111111,
            reqSignature: '--signature-placeholder--',
            partialData: '--partial-data--'
        };

    });


});

