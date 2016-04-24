'use strict';
//var util = require('util');
var EventEmitter = require('events').EventEmitter;
var lodash = require('lodash');

function NoticeBoard(csclient, credentials) {
  this.csclient = csclient;
  this.credentials = credentials;

  this.notices = {};
  this._updatingNB = null;
  this._waitingNBUpdate = [];
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
  var doUpdate = function () {
    self._updatingNB = self._waitingNBUpdate;
    self._waitingNBUpdate = [];
    self.csclient.fetchNotices(self.credentials, function (err, notices) {
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
      self._updatingNB.forEach(function (_cb) {if (_cb) _cb(err)});
      self._updatingNB = null;
      if (self._waitingNBUpdate.length > 0) doUpdate();
    });
  };
  self._waitingNBUpdate.push(cb);
  if (!self._updatingNB) doUpdate();
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
