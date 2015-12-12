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
var NoticeExtBackup = require('../lib/noticeExtBackup');

describe("noticeExtBackup", function () {
  var MOCK_ERR = new Error();

  var credentials;
  var csclient;
  var socket;
  var noticeBoard;
  var extBackup;
  beforeEach(function () {
    credentials = _.clone(MOCKS.CLIENTS[0].credentials, true);
    csclient = {
      deleteNotice: sinon.stub(),
      postNotice: sinon.stub()
    };
    socket = new EventEmitter();
    noticeBoard = NoticeBoard.create(csclient, credentials, socket);
    extBackup = new NoticeExtBackup(noticeBoard);
  });

  describe('constructor', function () {
    _.forEach({
      'newNotice/backupDevCompleted': '_handlerBackupDevCompleted',
      'newNotice/cancelBackup': '_handlerCancelBackup',
      'newNotice/backupDone': '_handlerBackupDone'
    }, function(fnName, event) {
      it(`should bind ${fnName} to '${event} event`, function () {
        sinon.spy(noticeBoard, 'on');
        var expected = sinon.stub();
        var bindStub = NoticeExtBackup.prototype[fnName].bind = sinon.stub().returns(expected);
        extBackup = new NoticeExtBackup(noticeBoard);
        sinon.assert.calledWith(bindStub, extBackup);
        sinon.assert.calledWithExactly(noticeBoard.on, event, expected);
      });
    });
  });

  describe('.startBackup', function () {
    beforeEach(function () {
      noticeBoard.postNotice = sinon.stub().yields();
    });
    it('should post a "backupInProgress" notice', function () {
      extBackup.startBackup(function () {
      });
      sinon.assert.calledWith(noticeBoard.postNotice, 'backupInProgress');
    });
    it('should put a backupId in notice data', function () {
      extBackup.startBackup(function () {
      });
      var noticeData = noticeBoard.postNotice.getCall(0).args[1];
      expect(noticeData.backupId).to.be.a('string');
      expect(noticeData.backupId).to.have.length.above(6);
    });
  });

  describe('._cleanBackup', function () {
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
      sinon.stub(noticeBoard, 'deleteNotice');
    });
    it('should not delete cancelBackup notice', function () {
      extBackup._cleanBackup();
      sinon.assert.neverCalledWith(noticeBoard.deleteNotice, '4');
    });
    it('should not delete backupDone notices', function () {
      extBackup._cleanBackup();
      sinon.assert.neverCalledWith(noticeBoard.deleteNotice, '5');
      sinon.assert.neverCalledWith(noticeBoard.deleteNotice, '7');
    });
    it('should not delete unrelated notices', function () {
      extBackup._cleanBackup();
      sinon.assert.neverCalledWith(noticeBoard.deleteNotice, '1');
    });
    it('should delete unrelated backup notices', function () {
      extBackup._cleanBackup();
      sinon.assert.calledWith(noticeBoard.deleteNotice, '6');
      sinon.assert.calledWith(noticeBoard.deleteNotice, '8');
    });
    it('should delete related notices', function () {
      extBackup._cleanBackup();
      sinon.assert.calledWith(noticeBoard.deleteNotice, '2');
      sinon.assert.calledWith(noticeBoard.deleteNotice, '3');
    });
  });

  describe('.cancelBackup', function () {
    it('should call _cleanBackup()', function () {
      sinon.spy(extBackup, '_cleanBackup');
      extBackup.cancelBackup();
      sinon.assert.calledWithExactly(extBackup._cleanBackup);
    });
    it('should post cancelBackup notice', function () {
      noticeBoard.notices = _.indexBy([
        {id: '2', type: 'backupInProgress', data: {backupId: '12345'}},
      ], 'id');
      sinon.stub(noticeBoard, 'postNotice');
      extBackup.cancelBackup();
      sinon.assert.calledWith(noticeBoard.postNotice, 'cancelBackup', {backupId: '12345'});
    });
  });

  describe('_handlerCancelBackup', function () {
    var MOCK_CANCELNOTICE = {id: '3', type: 'cancelBackup', copayerId: 'x', data: {backupId: '12345'}};
    beforeEach(function () {
      noticeBoard.notices = _.indexBy([
        {id: '2', type: 'backupInProgress', copayerId: 'x', data: {backupId: '12345'}},
      ], 'id');
    });
    it('should call _cleanBackup()', function () {
      sinon.spy(extBackup, '_cleanBackup');
      extBackup._handlerCancelBackup(MOCK_CANCELNOTICE);
      sinon.assert.calledOnce(extBackup._cleanBackup);
      sinon.assert.calledWithExactly(extBackup._cleanBackup, '12345');
    });
    it('should delete notice', function () {
      sinon.spy(noticeBoard, 'deleteNotice');
      extBackup._handlerCancelBackup(MOCK_CANCELNOTICE);
      sinon.assert.calledOnce(noticeBoard.deleteNotice);
      sinon.assert.calledWithExactly(noticeBoard.deleteNotice, '2');
    });
    it('should ignore self emitted notice', function () {
      sinon.stub(noticeBoard, 'deleteNotice').throws('should not be called');
      sinon.stub(extBackup, '_cleanBackup').throws('should not be called');
      var notice = _.clone(MOCK_CANCELNOTICE);
      notice.copayerId = credentials.copayerId;
      extBackup._handlerCancelBackup(notice);
    });
  });

  describe('.finishBackup', function () {
    it('should return error if not exists a backupInProgress', function () {
      extBackup.finishBackup(function (err, notice) {
        expect(err).to.exist;
        expect(err.message).to.equal('No backup notice');
      });
    });
    it('should post notice backupDevCompletd', function (done) {
      var MOCK_NOTICE = {id: '3', type: '_placeholder_'};
      noticeBoard.notices = _.indexBy([
        {id: '2', type: 'backupInProgress', data: {backupId: '12345'}},
      ], 'id');
      sinon.stub(noticeBoard, 'postNotice').yieldsAsync(null, MOCK_NOTICE);
      extBackup.finishBackup(function (err, notice) {
        expect(err).to.not.exist;
        sinon.assert.calledWith(noticeBoard.postNotice, 'backupDevCompleted', {backupId: '12345'});
        done();
      });
    });
  });

  describe('._handlerBackupDevCompleted', function () {
    var MOCK_NOTICE1 = {id: '3', type: 'backupDevCompleted', copayerId: 'x', data: {backupId: '12345'}};
    var MOCK_NOTICE2 = {id: '4', type: 'backupDevCompleted', copayerId: 'y', data: {backupId: '12345'}};
    it('shold do nothing', function () {
      noticeBoard.notices = _.indexBy([MOCK_NOTICE1], 'id');
      sinon.spy(noticeBoard, 'postNotice');
      extBackup._handlerBackupDevCompleted({}, MOCK_NOTICE1);
      sinon.assert.notCalled(noticeBoard.postNotice);
    });
    it('shold post backupDone notice', function () {
      noticeBoard.notices = _.indexBy([MOCK_NOTICE1, MOCK_NOTICE2], 'id');
      sinon.spy(noticeBoard, 'postNotice');
      extBackup._handlerBackupDevCompleted(MOCK_NOTICE1);
      sinon.assert.calledWith(noticeBoard.postNotice, 'backupDone');
    });
  });

  describe('._handlerBackupDone', function () {
    it('should call _cleanBackup()', function () {
      sinon.spy(extBackup, '_cleanBackup');
      extBackup._handlerBackupDone({id: '3', type: 'backupDone', copayerId: 'x'});
      sinon.assert.calledOnce(extBackup._cleanBackup);
      sinon.assert.calledWithExactly(extBackup._cleanBackup);
    })
  });
});
