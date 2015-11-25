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
var MOCK_SHAREDENCRIPTINGKEY = 'hiL2zY/82aRwOx7Y5UIYwQ==';  // derived from key b2a724fae2a1e09e79d49cc51bfb9d8035958e241ec820715f4b0df45fb335a7
var MOCK_COPAYERHASH = '-copayer-hash-placeholder-';
var MOCK_WALLETID = '7c9a7df9-990c-4de6-8f49-572ff0938216';

var MOCK_CREDENTIALSARRAY = [
    Credentials.fromExtendedPrivateKey('tprv8ZgxMBicQKsPfB68j6QH2jhxju935kx7eXqg28aMBD49wd7Crrqwv665r7ikjeMH8N1jb25J45LhTm7FwhqNRHp7Ddy6CcVfYpHW73zAdvP'),
    Credentials.fromExtendedPrivateKey('tprv8ZgxMBicQKsPe4EpMwgKFqMmJVqY4tPJdhRzZCx8hm9EaDUAw83Z5YazrVKriSDu1QTkf1GjFaFNB8maXYULooG8WeB2frrxsrEYUWq4hGZ'),
    // the third credential is derived from the first two using the algorithm for join v2
    Credentials.fromExtendedPrivateKey('tprv8ZgxMBicQKsPed74x6fBGh6UxpZ743sftFVukK281a3kdbDj4Set65MNQw4ekqSGBXJquQuNfokwZyD2fbqQsLa6bG8qSXQK4YVDopdejg4')
];
var MOCK_CREDENTIALS = MOCK_CREDENTIALSARRAY[0];
var MOCK_PUBLICKEYRING = MOCK_CREDENTIALSARRAY.map(function (c) {
    return {
        requestPubKey: c.requestPubKey,
        xPubKey: c.xPubKey
    };
});
for (var i=0; i<3; i++) {
    MOCK_CREDENTIALSARRAY[i].addWalletInfo(
        MOCK_WALLETID,
        '--wallet-name--',
        2,
        3,
        MOCK_WALLETPRIVKEY,
        '--copayer' + (i+1) +'--'
    );
    MOCK_CREDENTIALSARRAY[i].addPublicKeyRing(MOCK_PUBLICKEYRING);
}

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
        var fields = [
            'walletId',
            'sharedEncryptingKey',
            'copayerId',
            'requestPrivKey',
            'network',
        ];
        //_.forEach(completeCredentials, function (v, f_name) {
        fields.forEach(function(f_name) {
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

    function testJoinHttpRequest(exp_method, exp_url, exp_data, exp_credentials, done, cb) {
        var expected = {
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
            var pubkey = (new Bitcore.PrivateKey(exp_credentials.walletPrivKey)).toPublicKey().toString();
            var msg = JSON.stringify(expected.data);
            var signOk = walletUtils.verifyMessage(msg, callArg.data.joinSignature, pubkey);
            signOk.should.be.true;
            done();
        });
    }

    function testRetunedData(httpResponseData, expectedReturnedData, done, cb) {
        http_response.data = _.clone(httpResponseData);
        creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
        var csclient = new CSClient(creation_opts);
        cb(csclient, function (err, data) {
            if (_.isNull(expectedReturnedData)) {
                should.not.exist(data);
            } else {
                should.exist(data);
                data.should.deep.equal(expectedReturnedData);
            }
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
            var url = MOCK_OPTS.baseUrl + '/v1/wallets/' + MOCK_CREDENTIALS.walletId + '/setup';
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
        var MOCK_CREDENTIALS = _.clone(MOCK_CREDENTIALSARRAY[0]);
        MOCK_CREDENTIALS.walletPrivKey = MOCK_WALLETPRIVKEY;

        it('should return error with null argument', function (done) {
            testReturnedError(done, function (csclient, callback) {
                csclient.joinWallet(null, callback);
            });
        });
        it_testsIncompleteCredentials(MOCK_CREDENTIALS, function(csclient, credentials, callback) {
            csclient.joinWallet(credentials, callback);
        });
        it('should return error on getHash() error', function (done) {
            creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
            var csclient = new CSClient(creation_opts);
            sinon.stub(csclient, 'getHash').yields(new Error());
            csclient.joinWallet(MOCK_CREDENTIALS, function (err, data) {
                should.exist(err);
                should.not.exist(data);
                done();
            });
        });
        it('should call getHash with credentials', function(done) {
            creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
            var csclient = new CSClient(creation_opts);
            var mock = sinon.mock(csclient);
            mock.expects('getHash')
                .once()
                .withArgs(MOCK_CREDENTIALS)
                .yields(new Error());
            csclient.joinWallet(MOCK_CREDENTIALS, function (err, data) {
                mock.verify();
                done();
            });
        })
        it('should call httpRequest with correct params', function (done) {
            var url = MOCK_OPTS.baseUrl + '/v1/wallets/' + MOCK_CREDENTIALS.walletId
            var exp_data = {
                copayerHashSignature: '3045022100fe22b54f14c41a0b37d99526f7c0e0dd1f260859dc6d8ab0406ec66a66e4c9b3022002f3553c55d6938507cc40372152c28f2284b472339051963781ebc91692a2e3',
                walletPubKey: MOCK_WALLETPUBKEY,
                sharedEncryptingKey: MOCK_CREDENTIALS.sharedEncryptingKey
            };
            testHttpRequestCall('POST', url, exp_data, MOCK_CREDENTIALS, done, function(csclient, callback) {
                sinon.stub(csclient, 'getHash').yields(null, MOCK_COPAYERHASH);
                csclient.joinWallet(MOCK_CREDENTIALS, callback);
            });
        });
        it('should complete successfully', function (done) {
            testRetunedData({}, {}, done, function(csclient, callback) {
                sinon.stub(csclient, 'getHash').yields(null, MOCK_COPAYERHASH);
                csclient.joinWallet(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return error if http error', function (done) {
            testHttpError(done, function(csclient, callback) {
                sinon.stub(csclient, 'getHash').yields(null, MOCK_COPAYERHASH);
                csclient.joinWallet(MOCK_CREDENTIALS, callback);
            });
        });
    });

    describe('.joinServerFromDevice1', function () {
        var MOCK_CREDENTIALS = _.clone(MOCK_CREDENTIALSARRAY[0]);

        it('should return error with null argument', function (done) {
            testReturnedError(done, function (csclient, callback) {
                csclient.joinServerFromDevice1(null, callback);
            });
        });
        it_testsIncompleteCredentials(MOCK_CREDENTIALS, function(csclient, credentials, callback) {
            csclient.joinServerFromDevice1(credentials, callback);
        });
        it('should call httpRequest with correct params', function (done) {
            var url = MOCK_OPTS.baseUrl + '/v2/wallets/' + MOCK_CREDENTIALS.walletId + '/setup';
            var exp_data = {
                walletId: MOCK_WALLETID,
                copayerId1: MOCK_CREDENTIALS.copayerId,
                entropy1: 'Oxtf4DnG2Ff0FMuZ0MIn15Nc20QIdAGCeFV82YzAPE8=',
                network: MOCK_CREDENTIALS.network,
                walletPubKey: MOCK_WALLETPUBKEY,
                sharedEncKey: MOCK_CREDENTIALS.sharedEncryptingKey,
            };
            testJoinHttpRequest('POST', url, exp_data, MOCK_CREDENTIALS, done, function(csclient, callback) {
                csclient.joinServerFromDevice1(MOCK_CREDENTIALS, callback);
            });
        });
        it('should terminate', function (done) {
            testTerminationWithoutError(null, done, function(csclient, callback) {
                csclient.joinServerFromDevice1(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return error if bad response', function (done) {
            testBadHttpResponse(done, function(csclient, callback) {
                csclient.joinServerFromDevice1(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return error on http error', function (done) {
            testHttpError(done, function(csclient, callback) {
                csclient.getHash(MOCK_CREDENTIALS, callback);
            });
        });
    });

    describe('._joinV2Step2', function () {
        var MOCK_CREDENTIALS = _.clone(MOCK_CREDENTIALSARRAY[1]);

        it('should return error with null argument', function (done) {
            testReturnedError(done, function (csclient, callback) {
                csclient._joinV2Step2(null, callback);
            });
        });
        it_testsIncompleteCredentials(MOCK_CREDENTIALS, function(csclient, credentials, callback) {
            csclient._joinV2Step2(credentials, callback);
        });
        it('should call httpRequest with correct params', function (done) {
            var url = MOCK_OPTS.baseUrl + '/v2/wallets/' + MOCK_CREDENTIALS.walletId + '/setup';
            var exp_data = {
                walletId: MOCK_WALLETID,
                copayerId2: MOCK_CREDENTIALS.copayerId,
                entropy2: 'YD6FfjHGLX7fZC6IK0f+z1/6jOapnmExOCSmczW+2y0=',
            };
            testJoinHttpRequest('PATCH', url, exp_data, MOCK_CREDENTIALS, done, function(csclient, callback) {
                csclient._joinV2Step2(MOCK_CREDENTIALS, callback);
            });
        });
        it('should terminate', function (done) {
            testTerminationWithoutError({copayerHash: MOCK_COPAYERHASH}, done, function(csclient, callback) {
                csclient._joinV2Step2(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return correct hash', function (done) {
            testRetunedData({copayerHash: MOCK_COPAYERHASH}, MOCK_COPAYERHASH, done, function(csclient, callback) {
                csclient._joinV2Step2(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return error if bad response', function (done) {
            testBadHttpResponse(done, function(csclient, callback) {
                csclient._joinV2Step2(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return error "Copayer hash missing"', function (done) {
            http_response.data = {};
            creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
            var csclient = new CSClient(creation_opts);
            csclient._joinV2Step2(MOCK_CREDENTIALS, function (err, hash) {
                should.exist(err);
                _.startsWith(err.message, 'Copayer hash missing').should.be.true;
                should.not.exist(hash);
                done();
            });
        });
        it('should return error on http error', function (done) {
            testHttpError(done, function(csclient, callback) {
                csclient._joinV2Step2(MOCK_CREDENTIALS, callback);
            });
        });
    });

    describe('.joinServerFromDevice2', function () {
        var MOCK_CREDENTIALS = _.clone(MOCK_CREDENTIALSARRAY[1]);

        //TODO questi test sono stati compiati da joinServerFromDevice1 e appena aggiustati. Completare!

        it('should return error with null argument', function (done) {
            testReturnedError(done, function (csclient, callback) {
                csclient.joinServerFromDevice2(null, callback);
            });
        });
        it_testsIncompleteCredentials(MOCK_CREDENTIALS, function(csclient, credentials, callback) {
            csclient.joinServerFromDevice2(credentials, callback);
        });
        it('should return error on _joinV2Step2() error', function (done) {
            creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
            var csclient = new CSClient(creation_opts);
            sinon.stub(csclient, '_joinV2Step2').yields(new Error());
            csclient.joinServerFromDevice2(MOCK_CREDENTIALS, function (err) {
                should.exist(err);
                done();
            });
        });
        it('should call _joinV2Step2() with credentials', function(done) {
            creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
            var csclient = new CSClient(creation_opts);
            var mock = sinon.mock(csclient);
            mock.expects('_joinV2Step2')
                .once()
                .withArgs(MOCK_CREDENTIALS)
                .yields(new Error());
            csclient.joinServerFromDevice2(MOCK_CREDENTIALS, function (err, data) {
                mock.verify();
                done();
            });
        })
        it('should call httpRequest with correct params', function (done) {
            var url = MOCK_OPTS.baseUrl + '/v2/wallets/' + MOCK_CREDENTIALS.walletId;
            var exp_data = {
                walletId: MOCK_WALLETID,
                copayerHashSignature: '3045022100fe22b54f14c41a0b37d99526f7c0e0dd1f260859dc6d8ab0406ec66a66e4c9b3022002f3553c55d6938507cc40372152c28f2284b472339051963781ebc91692a2e3',
            };
            testJoinHttpRequest('POST', url, exp_data, MOCK_CREDENTIALS, done, function(csclient, callback) {
                sinon.stub(csclient, '_joinV2Step2').yields(null, MOCK_COPAYERHASH);
                csclient.joinServerFromDevice2(MOCK_CREDENTIALS, callback);
            });
        });
        it('should terminate', function (done) {
            testTerminationWithoutError(null, done, function(csclient, callback) {
                sinon.stub(csclient, '_joinV2Step2').yields(null, MOCK_COPAYERHASH);
                csclient.joinServerFromDevice2(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return error if bad response', function (done) {
            testBadHttpResponse(done, function(csclient, callback) {
                sinon.stub(csclient, '_joinV2Step2').yields(null, MOCK_COPAYERHASH);
                csclient.joinServerFromDevice2(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return error on http error', function (done) {
            testHttpError(done, function(csclient, callback) {
                sinon.stub(csclient, '_joinV2Step2').yields(null, MOCK_COPAYERHASH);
                csclient.getHash(MOCK_CREDENTIALS, callback);
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
            var url = MOCK_OPTS.baseUrl + '/v1/wallets/' + MOCK_CREDENTIALS.walletId + '/spendinglimit'
            testHttpRequestCall('GET', url, undefined, MOCK_CREDENTIALS, done, function(csclient, callback) {
                csclient.getSpendingLimit(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return the right data', function (done) {
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
            var url = MOCK_OPTS.baseUrl + '/v1/wallets/' + MOCK_CREDENTIALS.walletId + '/spendinglimit'
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
            var url = MOCK_OPTS.baseUrl + '/v1/wallets/' + MOCK_CREDENTIALS.walletId + '/spendinglimit'
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
            var url = MOCK_OPTS.baseUrl + '/v1/wallets/' + MOCK_CREDENTIALS.walletId + '/backup';
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
            var url = MOCK_OPTS.baseUrl + '/v1/wallets/' + MOCK_CREDENTIALS.walletId + '/backup';
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

    describe('.getBackupRequest', function () {
        var MOCK_HTTP_RESPONSE = {
            reqId: '--id-placeholder--',
            reqCopayer: MOCK_COPAYERHASH,
            reqTimestamp: 1111111,
            reqSignature: '--signature-placeholder--',
            partialData: '--partial-data--'
        };

        it('should return error with null argument', function (done) {
            testReturnedError(done, function (csclient, callback) {
                csclient.getBackupRequest(null, callback);
            });
        });
        it_testsIncompleteCredentials(MOCK_CREDENTIALS,  function(csclient, credentials, callback) {
            csclient.getBackupRequest(credentials, callback);
        });
        it('should terminate without error', function (done) {
            testTerminationWithoutError(MOCK_HTTP_RESPONSE, done, function(csclient, callback) {
                csclient.getBackupRequest(MOCK_CREDENTIALS, callback);
            });
        });
        it('should call httpRequest with correct params', function (done) {
            var url = MOCK_OPTS.baseUrl + '/v1/wallets/' + MOCK_CREDENTIALS.walletId + '/backup';
            testHttpRequestCall('GET', url, undefined, MOCK_CREDENTIALS, done, function(csclient, callback) {
                csclient.getBackupRequest(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return the right data', function (done) {
            testRetunedData(MOCK_HTTP_RESPONSE, MOCK_HTTP_RESPONSE, done, function(csclient, callback) {
                csclient.getBackupRequest(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return null data', function (done) {
            testRetunedData({}, null, done, function(csclient, callback) {
                csclient.getBackupRequest(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return error if bad response', function (done) {
            testBadHttpResponse(done, function(csclient, callback) {
                csclient.getBackupRequest(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return error if result is not OK', function (done) {
            http_response.data = {
                result: 'backup in progress'
            };
            creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
            testReturnedError(done, function (csclient, callback) {
                csclient.getBackupRequest(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return error if http error', function (done) {
            testHttpError(done, function(csclient, callback) {
                csclient.getBackupRequest(MOCK_CREDENTIALS, callback);
            });
        });
    });

    describe('.sendBackupRequestData', function () {
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

        it('should return error with null credentials', function (done) {
            testReturnedError(done, function (csclient, callback) {
                csclient.sendBackupRequestData(null, MOCK_PASSWORD, MOCK_BACKUPREQUEST, callback);
            });
        });
        it('should return error with null password', function (done) {
            testReturnedError(done, function (csclient, callback) {
                csclient.sendBackupRequestData(MOCK_CREDENTIALS, null, MOCK_BACKUPREQUEST, callback);
            });
        });
        it('should return error with null backupRequest', function (done) {
            testReturnedError(done, function (csclient, callback) {
                csclient.sendBackupRequestData(MOCK_CREDENTIALS, MOCK_PASSWORD, null, callback);
            });
        });
        it_testsIncompleteCredentials(MOCK_CREDENTIALS,  function(csclient, credentials, callback) {
            csclient.sendBackupRequestData(credentials, MOCK_PASSWORD, MOCK_BACKUPREQUEST, callback);
        });
        it('should return error with encrypted credentials', function (done) {
            testReturnedError(done, function (csclient, callback) {
                var credentials = Credentials.fromObj(MOCK_CREDENTIALS);
                credentials.setPrivateKeyEncryption('testPassw0rd');
                credentials.lock();
                csclient.sendBackupRequestData(credentials, MOCK_PASSWORD, MOCK_BACKUPREQUEST, callback);
            });
        });
        it('should return error if pending backup request was created from same copayer', function (done) {
            testReturnedError(done, function (csclient, callback) {
                var credentials = Credentials.fromObj(MOCK_CREDENTIALS);
                credentials.copayerId = MOCK_BACKUPREQUEST.req_copayer;
                csclient.sendBackupRequestData(credentials, MOCK_PASSWORD, MOCK_BACKUPREQUEST, callback);
            });
        });
        it('should terminate without error', function (done) {
            testTerminationWithoutError(MOCK_HTTP_RESPONSE, done, function(csclient, callback) {
                csclient.sendBackupRequestData(MOCK_CREDENTIALS, MOCK_PASSWORD, MOCK_BACKUPREQUEST, callback);
            });
        });
        it('should call httpRequest with correct params', function (done) {
            var url = MOCK_OPTS.baseUrl + '/v1/wallets/' + MOCK_CREDENTIALS.walletId + '/backup';
            var data = {
                reqId: MOCK_BACKUPREQUEST.reqId,
                partialData: '--partila-data-placeholder--'
            };
            testHttpRequestCall('PATCH', url, data, MOCK_CREDENTIALS, done, function(csclient, callback) {
                sinon.stub(csclient, '_prepareBackupPartialData').returns(data.partialData);
                csclient.sendBackupRequestData(MOCK_CREDENTIALS, MOCK_PASSWORD, MOCK_BACKUPREQUEST, callback);
            });
        });
        it('should return error if bad http response', function (done) {
            testBadHttpResponse(done, function(csclient, callback) {
                csclient.sendBackupRequestData(MOCK_CREDENTIALS, MOCK_PASSWORD, MOCK_BACKUPREQUEST, callback);
            });
        });
        it('should return error if result is not OK', function (done) {
            http_response.data = {
                result: 'no backup'
            };
            creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
            testReturnedError(done, function (csclient, callback) {
                csclient.sendBackupRequestData(MOCK_CREDENTIALS, MOCK_PASSWORD, MOCK_BACKUPREQUEST, callback);
            });
        });
        it('should return error if http error', function (done) {
            testHttpError(done, function(csclient, callback) {
                csclient.sendBackupRequestData(MOCK_CREDENTIALS, MOCK_PASSWORD, MOCK_BACKUPREQUEST, callback);
            });
        });
    });

    describe('._prepareBackupPartialData', function () {
        var MOCK_BACKUPREQUEST = {
            reqId: 'g8rmz7sl9qw',
            reqCopayer: MOCK_CREDENTIALS.copayerId,
            reqTimestamp: 1446541849132,
            reqSignature: '30440220105072dfda05db6864d9c79d4c873fe1afa266f88326750f2d9ab4d71f2659f8022015922c83fad16adc853c2d7919f0b9a012928c8c80afdbdd8c691470a0a40e19',
            partialData: undefined
        };
        var csclient;
        beforeEach(function () {
            csclient = new CSClient(creation_opts);
        });
        it('should return string', function () {
            var encData = csclient._prepareBackupPartialData(MOCK_CREDENTIALS, 'WeakPassw0rd', MOCK_BACKUPREQUEST);
            encData.should.be.a('string');
        });
        it('should return encrypted data using sharedEncryptingKey', function () {
            var encData = csclient._prepareBackupPartialData(MOCK_CREDENTIALS, 'WeakPassw0rd', MOCK_BACKUPREQUEST);
            expect(function () {
                walletUtils.decryptMessage(encData, MOCK_CREDENTIALS.sharedEncryptingKey);
            }).to.not.throw();
        });
        it('shoud return correct data', function () {
            var expected = {
                hX: 'XwjppXsb4+eQPJzgvthXXJRHXmTsvN+8bm7UqNKmcf8=',
                req_data: MOCK_BACKUPREQUEST
            };
            var encData = csclient._prepareBackupPartialData(MOCK_CREDENTIALS, 'WeakPassw0rd', MOCK_BACKUPREQUEST);
            var decData = JSON.parse(walletUtils.decryptMessage(encData, MOCK_CREDENTIALS.sharedEncryptingKey));
            decData.should.containSubset(expected);
            Object.keys(decData).should.have.length(4);
            should.exist(decData.data_signature);
            should.exist(decData.encryptedKey);
        });
        it('xPrivKey shoud be encrypted with password', function () {
            var encData = csclient._prepareBackupPartialData(MOCK_CREDENTIALS, 'WeakPassw0rd', MOCK_BACKUPREQUEST);
            var decData = JSON.parse(walletUtils.decryptMessage(encData, MOCK_CREDENTIALS.sharedEncryptingKey));
            var decKey;
            expect(function () {
                decKey = sjcl.decrypt('WeakPassw0rd', decData.encryptedKey);
            }).to.not.throw();
            decKey.should.equal(MOCK_CREDENTIALS.xPrivKey);
        });
        it('shoud sign data', function () {
            var encData = csclient._prepareBackupPartialData(MOCK_CREDENTIALS, 'WeakPassw0rd', MOCK_BACKUPREQUEST);
            var decData = JSON.parse(walletUtils.decryptMessage(encData, MOCK_CREDENTIALS.sharedEncryptingKey));
            var test = decData.data_signature;
            delete decData.data_signature;
            walletUtils.verifyMessage(JSON.stringify(decData), test, MOCK_CREDENTIALS.requestPubKey).should.be.true;
        });
    });

    describe('.buildBackupData', function () {
        var MOCK_BACKUPREQUEST = {
            reqId: 'g8rmz7sl9qw',
            reqCopayer: MOCK_CREDENTIALS.copayerId,
            reqTimestamp: 1446541849132,
            reqSignature: '30440220105072dfda05db6864d9c79d4c873fe1afa266f88326750f2d9ab4d71f2659f8022015922c83fad16adc853c2d7919f0b9a012928c8c80afdbdd8c691470a0a40e19',
            partialData: '{"iv":"X1mYOCzyvL5oigT8sv+4oA==","v":1,"iter":1,"ks":128,"ts":64,"mode":"ccm","adata":"","cipher":"aes","ct":"Zp/nnQpGM+0DP2KiUwNCOEDzDNSeLLobIWWE6YROqn7c75uveaGiJIPwPZIHUXLQ/9QOoydu7+1+POY0J0law2VM39E3pE5R/5tgpgui++yUCSILe2WBpCAW9hY0fFjvtl/SXmPtjohl2k9kjGyYzxkmGv8bwvLnE+88JrvI2IothgIYNWqdGlOpQXD0YCYC4pvyZUKbHu3AegWlJ23/f8tKvwZMVb09ctd5Bwvtrsx82gs27G2H2lD66GWjKb0JcjHt3ZbDpczZsvXIbvsYGOdQTL78tuzz09NfOezNbycWimxb17aSLuPerEouIlWsNcuM9s+/EeR/XkTFXQ67jsPoY4E4WCXFn13iFrNG/SHlHhu+t/WvOuYD54o9y2cFnz/bsbmDxhTUVgoYLGJPOaRmeQjQ1jhl4nkNFsMZtdRPrXu3YJ9wtBsfXnRSTOirKfSR+DiFW8ExPi0CI2m9q5GuW7raLkpe/r80VyumRUMc+NtIa0dmJc5Hn7q4CTzE7eT9kbVE2CF5z5vP4jiT9kTUUTnSzGsO8Nnj+RqED7Ilw6Um2DtcPN2q0SO3Y3kHnBgMmVfoU4T/L87Aw7qL/4e8Tz0kSrSVVfmA6BrefXTJxv3Mo+prij0NZ8sjWoMYllbGfyQXEokb8gq9bl+sgy06ZBHDw/9JRLK/F8NqZlFiwrTnVkCbVxzN0SmLNgwj9E/tMcTEFHIma2C4xDjz5e/8uQO0HcXChLBIeuhhGvPzb/Zm9VjVjLV9FbQLxwzIjXpO8t8o/B9/qFVAFLaS+MdrbFFVRtGm2/+eyk0JG/0GqCqavzp3OslAXSO77pNgL8qGuN0TOSHIoPsyccQvX7y0nvh2/LKeInUhYvoMsKPveOyqYVvThmzQkvngFg8K4Fnk/xMLRJHyf4qaLnGVw7zxoB4IpRiXeD989jaoCdHjCuoSG22j8/HIRPXzJc3US/FOnsiuU8z4Vy52J5pLPGKEKr13xlUEEfhcJtK7aTaoQLTNAI7SoPVyWkxyut7moD94o4dvSNz4/hywx/kageFFlr3jpIDzs1gQiSnahP09dAUmbjAxLDJs42NxupxSBVmfpRZhjxKgxtbKyUr7d5XXLtYvv86m9RE4BeDnomXKV0qd2p7oX8imdj/WipIQOiXN9HmfiQ=="}'
        };
        var MOCK_FULLBACKUPDATA = {
            "encPrivKey1": '{\"iv\":\"WnhiDqKEXS5XQMtfTfFEfA==\",\"v\":1,\"iter\":10000,\"ks\":128,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"salt\":\"CuE9F4LOQM0=\",\"ct\":\"aSS+4l44GFO3VJcaCDGMgYrlHc4C6DqmDjt9KbaTqSxwGdulwYvuHcL490VeHMnpFYF3N3Q3cxN97hWnOA3UxRMWMPZT9Icy5JW3DpPM3YVJ8GrSI0xEcZql2HBcJ4pt53TRiawDorxzCWUxFfVEorgA9W9uA4U=\"}',
            "xPubKey3": "tpubDCTtHnfCAAPzWCU8JdC5kcw84RrbQQW7EF7rbE42XCqWJfM1HabfbRDKn3zBzvpnVBbUarZcexfzi5hjJB4FLj9bSY9qzRRsJvUUtB6Cdcp"
        };
        it('should return backup data', function () {
            var csclient = new CSClient(creation_opts);
            var data = csclient.buildBackupData(MOCK_CREDENTIALS, MOCK_BACKUPREQUEST);
            data.should.containSubset(MOCK_FULLBACKUPDATA);
            should.exist(data.encPrivKey2);
            Object.keys(data).should.have.length(3);
        });
        it('should return encrypted xPrivKey', function () {
            var hX = 'XwjppXsb4+eQPJzgvthXXJRHXmTsvN+8bm7UqNKmcf8=';
            var csclient = new CSClient(creation_opts);
            var data = csclient.buildBackupData(MOCK_CREDENTIALS, MOCK_BACKUPREQUEST);
            var dec = sjcl.decrypt(hX, data.encPrivKey2);
            dec.should.equal(MOCK_CREDENTIALS.xPrivKey);
        });
        //TODO more tests
    });

    describe('._verifyBackupRequestSignature', function () {
        var csclient, reqId, timestamp, getParams;
        var MOCK_REQID = 'g8rmz7sl9qw';
        var MOCK_BACKUPREQUEST;

        beforeEach(function () {
            csclient = new CSClient(creation_opts);
            timestamp = Date.now();
            getParams = csclient._createBackupRequestParams(MOCK_CREDENTIALS.walletId, MOCK_REQID, timestamp);
            csclient._signRequest(MOCK_CREDENTIALS, getParams);
            MOCK_BACKUPREQUEST = {
                reqId: MOCK_REQID,
                reqCopayer: MOCK_CREDENTIALS.copayerId,
                reqTimestamp: timestamp,
                reqSignature: getParams.headers['x-signature'],
                partialData: '{"iv":"ms3g+1pSsNfK4KQCRzfcRA==","v":1,"iter":1,"ks":128,"ts":64,"mode":"ccm","adata":"","cipher":"aes","ct":"HqxZsZS/PVNCCcV6j9PLWe1QQlEIVT1fpj5Ai1R66WjsBAlB37B7OT92EiQCVpS001oLHrrtsMgq/5vMoXfoNZ/nbhxhOxItPDB6vpOccAWfDYLXjsXU4vmZ4QxvxcIdXw28r8T2NCGX3ZcCkANdZ4+oXSHC9hMkd3Q4DK4ux2VkRzIBMHWvFkFotDYr+VJKNsuR3s5uui9N2ngRUnaWkxg05D56EiWPL9n4VYnCI9pVhQaEiWk3v+BVg73BcXWG4Co7jXzeHjJGdPTDUGsx5NrL5yfC3DWrZknynmELheSuerKTZIU6/LcrBelJwl3+XkUW5HIBnEw02Y9/YileN2I+wHdFKLujKg/acE+heOOgJK8NJD2MhomiNxBJdox8drZToP3X3U6k8D0K6Kze1NPsD3ywq5EUG4if3+LmGTRbOJ6vFZrzfSGKGDvIx30b6uTDZGn4aEd/M7PAiVAC/PAsJwOhHkiXSyF5Be5xozMv+TrjMe8RD6xdtjYT5pHYfKU65Z8o+bi/ehEBV9NWdHX8d2WTA7ZBgx6QB1aiFeNenJBmp77MKbSVcdNeJoLMGSdbuXuxT1+uAHXBJDiT0h1Hp0/tdtQp7Nd1jk2SIEGSM7fgojbQA9ZsuAD0ZEaM0TnGjJa9EQ6lEUSHbbbv/xd2xdw4mDbNk2dAA+kj24F9hTUrI8oTvs5ZTjqPMV12ouhnPG0oIlX5W+VwqSxFk0CgXbUb2XEp5oLyOaSjAKVOCUSCk8xg5uyPfVYTe85qlE6WXPV27dYF5St3JqDrjYJgAms1n+ug+ijdehMGPdW863qSpnDrgyOVIf1/BLJyP688eH0iVr6A2AEl1R/mI0EQgPJYMnn/cVFsqE8eAZHiguq8uemHGbpROSC4a0z+vwzmjK28vRXhK9+SZhJ8MwN1xVPzAEb4fBbTilGIWtXsIjWdjzfq4Zfs4qnPyiPG1b+W1ypI5wzWeIqe6XZGiqHz"}'
            };
        });
        it('should return true', function () {
            csclient._verifyBackupRequestSignature(MOCK_BACKUPREQUEST, MOCK_CREDENTIALS)
                .should.be.true;
        });
        it('should return false', function () {
            MOCK_BACKUPREQUEST.reqId = '-wrong-id-';
            csclient._verifyBackupRequestSignature(MOCK_BACKUPREQUEST, MOCK_CREDENTIALS)
                .should.be.false;
        });
    });

    describe('.decryptBackupData', function () {
        //TODO tests for decryptBackupData()
    });

    describe('.processTxps', function () {
        var MOCK_HTTP_RESPONSE = {
            result: 'Partial error',
            verdicts: {
                '01448365052759fc58843e-e651-493a-bd5e-3d87ae779bd8': 'signed',
                '09876543210987ab45263d-b437-000a-eee3-035d89b0a3ff': 'over spending limit',
                '4632908614509860124845-5472-1361-5128-981609404165': 'Error',
            }
        };

        it('should return error with null argument', function (done) {
            testReturnedError(done, function (csclient, callback) {
                csclient.processTxps(null, callback);
            });
        });
        it_testsIncompleteCredentials(MOCK_CREDENTIALS,  function(csclient, credentials, callback) {
            csclient.processTxps(credentials, callback);
        });
        it('should terminate without error', function (done) {
            testTerminationWithoutError(MOCK_HTTP_RESPONSE, done, function(csclient, callback) {
                csclient.processTxps(MOCK_CREDENTIALS, callback);
            });
        });
        it('should call httpRequest with correct params', function (done) {
            var url = MOCK_OPTS.baseUrl + '/v2/wallets/' + MOCK_CREDENTIALS.walletId + '/txps';
            testHttpRequestCall('GET', url, undefined, MOCK_CREDENTIALS, done, function(csclient, callback) {
                csclient.processTxps(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return the right data', function (done) {
            testRetunedData(MOCK_HTTP_RESPONSE, MOCK_HTTP_RESPONSE, done, function(csclient, callback) {
                csclient.processTxps(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return null data', function (done) {
            testRetunedData({}, null, done, function(csclient, callback) {
                csclient.processTxps(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return error if bad response', function (done) {
            testBadHttpResponse(done, function(csclient, callback) {
                csclient.processTxps(MOCK_CREDENTIALS, callback);
            });
        });
        it('should return error if http error', function (done) {
            testHttpError(done, function(csclient, callback) {
                csclient.processTxps(MOCK_CREDENTIALS, callback);
            });
        });
    });

});

