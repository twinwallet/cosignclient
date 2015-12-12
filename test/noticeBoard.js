'use strict';

var _ = require('lodash');
var EventEmitter = require('events');
var sinon = require('sinon');
var chai = require('chai');
var assert = chai.assert,
    expect = chai.expect,
    should = chai.should();

var MOCKS = require('./mocks');
var CSClient = require('../lib/csclient');
var NoticeBoard = require('../lib/noticeBoard');

describe("noticeBoard", function () {
  var MOCK_ERR = new Error();

  var credentials;
  var csclient;
  var socket;
  beforeEach(function () {
    credentials = _.clone(MOCKS.CLIENTS[0].credentials, true);
    csclient = sinon.stub();
    socket = new EventEmitter();
  });

  describe('initialization', function () {
    it('should return a new NoticeBoad', function () {
      var nb = NoticeBoard.create(csclient, credentials, socket);
      expect(nb).to.be.an.instanceof(NoticeBoard);
    });
    it('should initialize fields', function () {
      var nb = NoticeBoard.create(csclient, credentials, socket);
      expect(nb.csclient).to.equal(csclient);
      expect(nb.credentials).to.equal(credentials);
      expect(nb.notices).to.deep.equal({});
    });
    it('should listen notice event on socket', function() {
      sinon.spy(socket, 'on');
      var nb = NoticeBoard.create(csclient, credentials, socket);
      sinon.assert.calledOnce(socket.on);
      sinon.assert.calledWith(socket.on, 'notice');
    })
  });

  describe('operations', function () {
    var noticeBoard;
    beforeEach(function () {
      noticeBoard = NoticeBoard.create(csclient, credentials, socket);
    });

    describe('on "notice" event', function() {
      it('should update notice board', function(done) {
        sinon.stub(noticeBoard, 'updateNoticeBoard', function() {
          sinon.assert.calledOnce(noticeBoard.updateNoticeBoard);
          done();
        });
        socket.emit('notice', {walletId: credentials.walletId});
      })
    });

    describe('.postNotice', function () {
      var MOCK_TYPE = 'test_type';
      var MOCK_NOTICE = {
        id: '_placeholder_',
        type: MOCK_TYPE
      };
      beforeEach(function () {
        csclient.postNotice = sinon.stub().yields(null, MOCK_NOTICE);
      });
      it('should call csclient.postNotice()', function () {
        csclient.postNotice = sinon.expectation.create('postNotice')
          .once()
          .withArgs(credentials, MOCK_TYPE, {});
        noticeBoard.postNotice(MOCK_TYPE, {}, function() {});
        csclient.postNotice.verify();
      });
      it('should return error', function (done) {
        csclient.postNotice = sinon.stub().yields(MOCK_ERR);
        noticeBoard.postNotice(MOCK_TYPE, {}, function(err, notice) {
          expect(err).to.equal(MOCK_ERR);
          done();
        });
      });
      it('should return notice', function (done) {
        noticeBoard.postNotice(MOCK_TYPE, {}, function(err, notice) {
          expect(err).to.not.exist;
          expect(notice).to.equal(MOCK_NOTICE);
          done();
        });
      });
      it('should save notice to noticeBoard', function (done) {
        noticeBoard.postNotice(MOCK_TYPE, {}, function(err, notice) {
          expect(noticeBoard.notices[notice.id]).to.equal(MOCK_NOTICE);
          done();
        });
      });
      it('should emit "newNotice/test_type" event', function (done) {
        var mock = sinon.mock(noticeBoard).expects('emit')
          .once()
          .withArgs('newNotice/test_type', MOCK_NOTICE);
        noticeBoard.postNotice(MOCK_TYPE, {}, function() {
          mock.verify();
          done();
        });
      });
      it('should not emit newNotice event', function (done) {
        noticeBoard.notices[MOCK_NOTICE.id] = MOCK_NOTICE;
        sinon.spy(noticeBoard, 'emit');
        noticeBoard.postNotice(MOCK_TYPE, {}, function(err, notice) {
          sinon.assert.neverCalledWith(noticeBoard.emit, 'newNotice/test_type');
          done();
        });
      });
    });

    describe('.deleteNotice', function () {
      var MOCK_NOTICEID = '_placeholder_';
      beforeEach(function () {
        csclient.deleteNotice = sinon.stub().yields();
        noticeBoard.notices[MOCK_NOTICEID] = {id: MOCK_NOTICEID, type: 'test'};
      });
      it('should call csclient.deleteNotice()', function () {
        csclient.deleteNotice = sinon.expectation.create('deleteNotice')
          .once()
          .withArgs(credentials, MOCK_NOTICEID);
        noticeBoard.deleteNotice(MOCK_NOTICEID, function() {});
        csclient.deleteNotice.verify();
      });
      it('should return error', function (done) {
        csclient.deleteNotice = sinon.stub().yields(MOCK_ERR);
        noticeBoard.deleteNotice(MOCK_NOTICEID, function(err) {
          expect(err).to.equal(MOCK_ERR);
          done();
        });
      });
      it('should complete without errors', function (done) {
        noticeBoard.deleteNotice(MOCK_NOTICEID, function(err) {
          expect(err).to.not.exist;
          done();
        });
      });
      it('should delete notice from noticeBoard', function (done) {
        noticeBoard.deleteNotice(MOCK_NOTICEID, function(err) {
          expect(noticeBoard.notices[MOCK_NOTICEID]).to.not.exist;
          done();
        });
      });
      it('should not emit newNotice event', function (done) {
        sinon.spy(noticeBoard, 'emit');
        noticeBoard.deleteNotice(MOCK_NOTICEID, function(err) {
          sinon.assert.neverCalledWith(noticeBoard.emit, 'newNotice/test');
          done();
        });
      });
    });

    describe('.updateNoticeBoard', function () {
      var MOCK_BOARD = {
        '_1_': {id: '_1_', type: 'test'},
      };
      var MOCK_NEWNOTICES = [
        {id: '_1_', type: 'test'},
        {id: '_2_', type: 'test'},
      ];
      beforeEach(function () {
        noticeBoard.notices = MOCK_BOARD;
        csclient.fetchNotices = sinon.stub().yields(null, MOCK_NEWNOTICES);
      });

      it('should call csclient.fetchNotices()', function () {
        csclient.fetchNotices = sinon.expectation.create('fetchNotices')
          .once()
          .withArgs(credentials);
        noticeBoard.updateNoticeBoard(function() {});
        csclient.fetchNotices.verify();
      });
      it('should return error', function (done) {
        csclient.fetchNotices = sinon.stub().yields(MOCK_ERR);
        noticeBoard.updateNoticeBoard(function (err) {
          expect(err).to.equal(MOCK_ERR);
          done();
        });
      });
      it('should complete without errors', function (done) {
        noticeBoard.updateNoticeBoard(function (err) {
          expect(err).to.not.exist;
          done();
        });
      });
      it('should update noticeBoard on add', function (done) {
        var expected = _.indexBy(MOCK_NEWNOTICES, 'id');
        noticeBoard.updateNoticeBoard(function (err) {
          expect(noticeBoard.notices).to.deep.equal(expected);
          done();
        });
      });
      it('should update noticeBoard on delete', function (done) {
        csclient.fetchNotices = sinon.stub().yields(null, []);
        noticeBoard.updateNoticeBoard(function (err) {
          expect(noticeBoard.notices).to.deep.equal({});
          done();
        });
      });
      it('should emit "newNotice/test" event only for added notice', function (done) {
        var mock = sinon.mock(noticeBoard).expects('emit')
          .once()
          .withArgs('newNotice/test', MOCK_NEWNOTICES[1]);
        noticeBoard.updateNoticeBoard(function (err) {
          mock.verify();
          done();
        });
      });
    });

    describe('.filterNotices', function () {
      beforeEach(function () {
        noticeBoard.notices = _.indexBy([
          {id: '1', type: 'test'},
          {id: '2', type: 'backupInProgress', data: {backupId: '12345'}},
          {id: '3', type: 'backupDevCompleted', data: {backupId: '12345'}},
          {id: '4', type: 'cancelBackup', data: {backupId: '12345'}},
          {id: '5', type: 'backupDone'},
          {id: '6', type: 'backupInProgress', data: {backupId: '00001'}},
          {id: '7', type: 'backupDone'},
          {id: '8', type: 'backupDevCompleted', data: {backupId: '00002'}},
        ], 'id');
      });
      it('should return an array', function () {
        var actual = noticeBoard.filterNotices({id: '1'});
        expect(actual).to.be.an('array');
      });
      it('should find one element', function () {
        var actual = noticeBoard.filterNotices({id: '1'});
        expect(actual).to.have.length(1);
        expect(actual[0]).to.equal(noticeBoard.notices['1']);
      });
      it('should find two elements', function () {
        var actual = noticeBoard.filterNotices({type: 'backupDone'});
        expect(actual).to.have.length(2);
        expect(actual[0]).to.equal(noticeBoard.notices['5']);
        expect(actual[1]).to.equal(noticeBoard.notices['7']);
      });
    });

  });
});
