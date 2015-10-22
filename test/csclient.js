'use strict';

var _ = require('lodash');
var sinon = require('sinon');
var chai = require('chai');
var should = chai.should();
var expect = chai.expect;
var chaiSubset = require('chai-subset');
chai.use(chaiSubset);
var walletUtils = require('bitcore-wallet-utils');
var Bitcore = walletUtils.Bitcore;

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
    network: Bitcore.Networks.livenet
};

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

var ERR = new Error('err');
function testErr(done, msg) {
    return function (err, data) {
        should.exist(err);
        if (!msg)
            err.should.equal(ERR);
        else
            err.message.should.equal(msg);
        should.not.exist(data);
        done();
    };
}

function signatureShouldBeOk(callArg, expected) {
    var msg = expected.method.toLocaleLowerCase() + '|' + expected.url + '|' + JSON.stringify(expected.data || {});
    var signOk = walletUtils.verifyMessage(msg, callArg.headers['x-signature'], MOCK_REQPUBKEY);
    signOk.should.be.true;
}

describe('CSClient', function () {
    var MOCK_OPTS = {
        baseUrl: 'http://localhost:1234/cosign',
        httpRequest: MOCK_REQUEST_NULL,
        bwutils: walletUtils,
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

    function testNullArgument(method, done) {
        var csclient = new CSClient(creation_opts);
        csclient[method](null, function (err, data) {
            should.exist(err);
            should.not.exist(data);
            done();
        });
    }

    function it_testsIncompleteCredentials(method, completeCredentials) {
        _.forEach(completeCredentials, function (v, f_name) {
            it('should return error with missing credential field ' + f_name, function (done) {
                var csclient = new CSClient(creation_opts);
                var credentials = _.clone(completeCredentials);
                delete credentials[f_name];
                csclient[method](credentials, function (err, data) {
                    should.exist(err);
                    should.not.exist(data);
                    done();
                });
            });
        });
    }

    function testTerminationWithoutError(method, httpResponseData, done) {
        http_response.data = _.clone(httpResponseData);
        creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
        var csclient = new CSClient(creation_opts);
        csclient[method](MOCK_CREDENTIALS, function (err, hash) {
            should.not.exist(err);
            done();
        });
    }

    function testRetunedData(method, httpResponseData, expectedReturnedData, done) {
        http_response.data = _.clone(httpResponseData);
        creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
        var csclient = new CSClient(creation_opts);
        csclient[method](MOCK_CREDENTIALS, function (err, data) {
            should.exist(data);
            data.should.deep.equal(expectedReturnedData);
            done();
        });
    }

    function testBadHttpResponse(method, done) {
        http_response.data = 'error';
        creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
        var csclient = new CSClient(creation_opts);
        csclient[method](MOCK_CREDENTIALS, function (err, data) {
            should.exist(err);
            should.not.exist(data);
            done();
        });
    }

    function testHttpError(method, done) {
        http_response.data = null;
        http_response.status = 500;
        creation_opts.httpRequest = sinon.stub().returns(errorHttpHelper(http_response));
        var csclient = new CSClient(creation_opts);
        csclient[method](MOCK_CREDENTIALS, function (err, hash) {
            should.exist(err);
            should.not.exist(hash);
            done();
        });
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
            testNullArgument('getHash', done);
        });
        it_testsIncompleteCredentials('getHash', MOCK_CREDENTIALS);
        it('should terminate', function (done) {
            testTerminationWithoutError('getHash', {copayerHash: MOCK_COPAYERHASH}, done);
        });
        it('should call httpRequest with correct params', function (done) {
            var expected = {
                data: {network: MOCK_CREDENTIALS.network},
                headers: {
                    'x-client-version': 'CSClient',
                    'x-identity': MOCK_CREDENTIALS.copayerId,
                },
                method: 'POST',
                url: MOCK_OPTS.baseUrl + '/wallets/' + MOCK_CREDENTIALS.walletId + '/setup'
            };

            var reqStub = creation_opts.httpRequest = sinon.expectation.create()
                .once()
                .returns(successHttpHelper(http_response));
            var csclient = new CSClient(creation_opts);
            csclient.getHash(MOCK_CREDENTIALS, function (err, hash) {
                reqStub.verify();
                var callArg = reqStub.getCall(0).args[0];
                callArg.should.containSubset(expected);
                signatureShouldBeOk(callArg, expected);
                done();
            });
        });
        it('should return correct hash', function (done) {
            testRetunedData('getHash', {copayerHash: MOCK_COPAYERHASH}, MOCK_COPAYERHASH, done);
        });
        it('should return error if bad response', function (done) {
            testBadHttpResponse('getHash', done);
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
            testHttpError('getHash', done);
        });
    });

    describe('.joinWallet', function () {
        it('should return error with null argument', function (done) {
            testNullArgument('joinWallet', done);
        });
        var MOCK_CREDENTIALS2 = _.clone(MOCK_CREDENTIALS);
        MOCK_CREDENTIALS2.walletPrivKey = MOCK_WALLETPRIVKEY;
        it_testsIncompleteCredentials('joinWallet', MOCK_CREDENTIALS2);
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
            var expected = {
                data: {
                    copayerHashSignature: '3045022100fe22b54f14c41a0b37d99526f7c0e0dd1f260859dc6d8ab0406ec66a66e4c9b3022002f3553c55d6938507cc40372152c28f2284b472339051963781ebc91692a2e3',
                    walletPubKey: MOCK_WALLETPUBKEY,
                    sharedEncryptingKey: MOCK_CREDENTIALS2.sharedEncryptingKey
                },
                headers: {
                    'x-client-version': 'CSClient',
                    'x-identity': MOCK_CREDENTIALS2.copayerId,
                },
                method: 'POST',
                url: MOCK_OPTS.baseUrl + '/wallets/' + MOCK_CREDENTIALS2.walletId
            };

            var reqStub = creation_opts.httpRequest = sinon.expectation.create()
                .once()
                .returns(successHttpHelper(http_response));
            var csclient = new CSClient(creation_opts);
            sinon.stub(csclient, 'getHash').yields(null, MOCK_COPAYERHASH);
            csclient.joinWallet(MOCK_CREDENTIALS2, function (err, hash) {
                reqStub.verify();
                var callArg = reqStub.getCall(0).args[0];
                callArg.should.containSubset(expected);
                signatureShouldBeOk(callArg, expected);
                done();
            });
        });
        it('should complete successfully', function (done) {
            //http_response.data = {};
            creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
            var csclient = new CSClient(creation_opts);
            sinon.stub(csclient, 'getHash').yields(null, MOCK_COPAYERHASH);
            csclient.joinWallet(MOCK_CREDENTIALS2, function (err, data) {
                should.not.exist(err);
                should.exist(data);
                data.should.equal(http_response.data);
                done();
            });
        });
        it('should return error if http error', function (done) {
            http_response.data = null;
            http_response.status = 500;
            creation_opts.httpRequest = sinon.stub().returns(errorHttpHelper(http_response));
            var csclient = new CSClient(creation_opts);
            sinon.stub(csclient, 'getHash').yields(null, MOCK_COPAYERHASH);
            csclient.joinWallet(MOCK_CREDENTIALS2, function (err, hash) {
                should.exist(err);
                should.not.exist(hash);
                done();
            });
        });
    });

    describe('.getSpendingLimit', function () {
        var MOCK_HTTP_RESPONSE = {spendingLimit: 1000, consumed: 222, pendingLimit: 2000, pendingLimitApproved: false};

        it('should return error with null argument', function (done) {
            testNullArgument('getSpendingLimit', done);
        });
        it_testsIncompleteCredentials('getSpendingLimit', MOCK_CREDENTIALS);
        it('should terminate without error', function (done) {
            testTerminationWithoutError('getSpendingLimit', MOCK_HTTP_RESPONSE, done);
        });
        it('should call httpRequest with correct params', function (done) {
            var expected = {
                headers: {
                    'x-client-version': 'CSClient',
                    'x-identity': MOCK_CREDENTIALS.copayerId,
                },
                method: 'GET',
                url: MOCK_OPTS.baseUrl + '/wallets/' + MOCK_CREDENTIALS.walletId + '/spendinglimit'
            };
            http_response.data = _.clone(MOCK_HTTP_RESPONSE);
            var reqStub = creation_opts.httpRequest = sinon.expectation.create()
                .once()
                .returns(successHttpHelper(http_response));
            var csclient = new CSClient(creation_opts);
            csclient.getSpendingLimit(MOCK_CREDENTIALS, function (err, data) {
                reqStub.verify();
                var callArg = reqStub.getCall(0).args[0];
                callArg.should.containSubset(expected);
                should.not.exist(callArg.data);
                signatureShouldBeOk(callArg, expected);
                done();
            });
        });
        it('should return correct data', function (done) {
            testRetunedData('getSpendingLimit', MOCK_HTTP_RESPONSE, MOCK_HTTP_RESPONSE, done);
        });
        it('should return error if bad response', function (done) {
            testBadHttpResponse('getSpendingLimit', done);
        });
        it('should return error', function (done) {
            testHttpError('getSpendingLimit', done);
        });
    });

    describe('.requestSpendingLimit', function () {

    });

    describe('.confirmSpendingLimit', function () {

    });

    describe('.initNotifications', function () {

    });

});

