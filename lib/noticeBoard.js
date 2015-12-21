'use strict';
//var util = require('util');
var EventEmitter = require('events').EventEmitter;
var lodash = require('lodash');

function NoticeBoard(csclient, credentials) {
  this.csclient = csclient;
  this.credentials = credentials;

  this.notices = {};
}

//util.inherits(NoticeBoard, events.EventEmitter);
NoticeBoard.super_ = EventEmitter;
NoticeBoard.prototype = Object.create(EventEmitter.prototype, {
  constructor: {
    value: NoticeBoard,
    enumerable: false,
    writable: true,
    configurable: true
  }
});

NoticeBoard.create = function (csclient, credentials, socket) {
  var noticeBoard = new NoticeBoard(csclient, credentials);

  socket.on('notice', function (data) {
    if (data.walletId === credentials.walletId) {
      noticeBoard.updateNoticeBoard();
    } else {
      console.error('notice for wrong walletId');
    }
  });
  
  return noticeBoard;
};

NoticeBoard.prototype.updateNoticeBoard = function (cb){
  function error(err) {
    console.log(err);
    if (cb) cb(err);
  }
  var self = this;
  this.csclient.fetchNotices(this.credentials, function (err, notices) {
    if (err) return error(err);
    var oldNotices = self.notices || [];
    self.notices = lodash.indexBy(notices, 'id');
    var newNotices = lodash.select(notices, function (n) {
      return !oldNotices[n.id];
    });
    newNotices.forEach(function (notice) {
      self.emit('newNotice/' + notice.type, notice);
    });
    self.emit('noticesUpdated');
    if (cb) cb(err);
  });
};

NoticeBoard.prototype.filterNotices = function (where) {
  return lodash.filter(this.notices, where);
};

NoticeBoard.prototype.postNotice = function (type, data, cb) {
  function error(err) {
    console.log(err);
    if (cb) cb(err);
  }
  var self = this;
  self.csclient.postNotice(self.credentials, type, data, function(err, notice) {
    if (err) return error(err);
    if (!self.notices[notice.id]) {
      self.notices[notice.id] = notice;
      self.emit('newNotice/' + notice.type, notice);
    }
    if (cb) cb(null, notice);
  });
};

NoticeBoard.prototype.deleteNotice = function (id, cb) {
  function error(err) {
    console.log(err);
    if (cb) cb(err);
  }
  var self = this;
  self.csclient.deleteNotice(self.credentials, id, function(err) {
    if (err) return error(err);
    delete self.notices[id];
    if (cb) cb();
  });
};

module.exports = NoticeBoard;
