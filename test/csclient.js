'use strict';

var _ = require('lodash');
var sinon = require('sinon');
var chai = require('chai');
var should = chai.should();
var expect = chai.expect;
var chaiSubset = require('chai-subset');
chai.use(chaiSubset);
//var Promise = require('promise');
//var Q = require('q');
var walletUtils = require('bitcore-wallet-utils');
var Bitcore = walletUtils.Bitcore;

var CSClient = require('../lib/csclient');

// request key is the derivation m/1'/0 of tprv8ZgxMBicQKsPfB68j6QH2jhxju935kx7eXqg28aMBD49wd7Crrqwv665r7ikjeMH8N1jb25J45LhTm7FwhqNRHp7Ddy6CcVfYpHW73zAdvP
var MOCK_REQPRIVKEY = '2fde5d887c7c60c723d46947706b747a84a019e3863bb00a8ad2127f4ec09273';
var MOCK_REQPUBKEY = (new Bitcore.PrivateKey(MOCK_REQPRIVKEY)).toPublicKey().toString();
var MOCK_REQUEST_NULL = function() { return { then: function(s,e) {} } };
var MOCK_SHAREDENCRIPTINGKEY = '-shared-encripting-key-placeholder-';
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
    var msg = 'post|' + expected.url + '|' + JSON.stringify(expected.data);
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
    var MOCK_HTTP_RESPONSE= {
        data: {},
        status: '',
        config: '',
        headers: ''
    };
    var http_response;
    beforeEach(function () {
        creation_opts = _.clone(MOCK_OPTS);
        http_response = _.clone(MOCK_HTTP_RESPONSE);
    });

    describe('constructor', function () {
        it('should throw error with null opts', function () {
            expect(function () {
                var csclient = new CSClient(null);
            }).to.throw(Error);
        });
        _.forEach(MOCK_OPTS, function (v, parameter) {
            it('should throw error with missing parameter ' + parameter, function (done) {
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
        it('should return error with null argument', function () {
            var csclient = new CSClient(creation_opts);
            csclient.getHash(null, function (err, hash) {
                should.exist(err);
                should.not.exist(hash);
                done();
            });
        });
        _.forEach(MOCK_CREDENTIALS, function (v, f_name) {
            it('should return error with missing credential field ' + f_name, function (done) {
                var credentials = _.clone(MOCK_CREDENTIALS);
                delete credentials[f_name];
                var csclient = new CSClient(creation_opts);
                csclient.getHash(credentials, function (err, data) {
                    should.exist(err);
                    should.not.exist(data);
                });
            });
        });
        it('should terminate', function (done) {
            creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
            var csclient = new CSClient(creation_opts);
            csclient.getHash(MOCK_CREDENTIALS, function (err, hash) {
                done();
            });
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
            throw 'not implemented yet';
        });
        it('should return error if bad hash', function (done) {
            throw 'not implemented yet';
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
            http_response.data = null;
            creation_opts.httpRequest = sinon.stub().returns(errorHttpHelper(http_response));
            var csclient = new CSClient(creation_opts);
            csclient.getHash(MOCK_CREDENTIALS, function (err, hash) {
                should.exist(err);
                should.not.exist(hash);
                done();
            });
        });
    });

    describe('.joinWallet', function () {
        it('should return error with null argument', function () {
            var csclient = new CSClient(creation_opts);
            csclient.joinWallet(null, function (err, hash) {
                should.exist(err);
                should.not.exist(hash);
                done();
            });
        });
        _.forEach(MOCK_CREDENTIALS, function (v, f_name) {
            it('should return error with missing credential field ' + f_name, function (done) {
                var credentials = _.clone(MOCK_CREDENTIALS);
                delete credentials[f_name];
                var csclient = new CSClient(creation_opts);
                csclient.joinWallet(credentials, function (err, data) {
                    should.exist(err);
                    should.not.exist(data);
                    done();
                });
            });
        });
        it('should return error on getHash() error', function (done) {
            creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
            var csclient = new CSClient(creation_opts);
            sinon.stub(csclient, 'getHash').yields(new Error());
            csclient.joinWallet(credentials, function (err, data) {
                should.exist(err);
                should.not.exist(data);
                done();
            });
        });
        it('should call httpRequest with correct params')
        it('should complete successfully')
        it('should return error if http error')
    });

    describe('.getSpendingLimit', function () {
        it('should return error with null argument', function () {
            var csclient = new CSClient(creation_opts);
            csclient.getSpendingLimit(null, function (err, hash) {
                should.exist(err);
                should.not.exist(hash);
                done();
            });
        });
        _.forEach(MOCK_CREDENTIALS, function (v, f_name) {
            it('should return error with missing credential field ' + f_name, function (done) {
                var credentials = _.clone(MOCK_CREDENTIALS);
                delete credentials[f_name];
                var csclient = new CSClient(creation_opts);
                csclient.getSpendingLimit(credentials, function (err, data) {
                    should.exist(err);
                    should.not.exist(data);
                    done();
                });
            });
        });
        it('should return error on getHash() error', function (done) {
            creation_opts.httpRequest = sinon.stub().returns(successHttpHelper(http_response));
            var csclient = new CSClient(creation_opts);
            sinon.stub(csclient, 'getHash').yields(new Error());
            csclient.getSpendingLimit(credentials, function (err, data) {
                should.exist(err);
                should.not.exist(data);
                done();
            });
        });
        it('should call httpRequest with correct params')
        it('should complete successfully')
        it('should return error if http error')
    });

});

