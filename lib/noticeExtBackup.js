'use strict';

var lodash = require('lodash');
var NoticeBoard = require('./noticeBoard');

function ExtBackup(noticeBoard) {
  if (!(this instanceof ExtBackup)) return new ExtBackup(noticeBoard);
  this.noticeBoard = noticeBoard;

  noticeBoard.on('newNotice/cancelBackup', ExtBackup.prototype._handlerCancelBackup.bind(this));
  noticeBoard.on('newNotice/backupDevCompleted', ExtBackup.prototype._handlerBackupDevCompleted.bind(this));
  noticeBoard.on('newNotice/backupDone', ExtBackup.prototype._handlerBackupDone.bind(this));
}

ExtBackup.prototype.startBackup = function (cb) {
  var backupId = Math.random().toString(36).substring(8);
  this.noticeBoard.postNotice('backupInProgress', {backupId: backupId}, cb);
};

ExtBackup.prototype._cleanBackup = function (backupId) {
  var self = this;
  var ids;
  if (backupId) {
    ids = [backupId];
  } else {
    ids = lodash(this.noticeBoard.notices)
      .filter(function (n) {
        return n.data && n.data.backupId;
      })
      .map(function (n) {
        return n.data.backupId;
      })
      .uniq().value();
  }
  ids.forEach(function (id) {
    self.noticeBoard.filterNotices({data: {backupId: id}}).forEach(function (n) {
      if (n.type !== 'cancelBackup' && n.type !== 'backupDone')
        self.noticeBoard.deleteNotice(n.id);
    });
  });
};

ExtBackup.prototype.cancelBackup = function () {
  var self = this;
  self.noticeBoard.filterNotices({type: 'backupInProgress'}).forEach(function(n) {
    self.noticeBoard.postNotice('cancelBackup', {backupId: n.data.backupId});
  });
  self._cleanBackup();
};

ExtBackup.prototype._handlerCancelBackup = function (notice) {
  if (notice.copayerId === this.noticeBoard.credentials.copayerId) return;
  if (!notice.data || !notice.data.backupId) {
    console.error('Invalid Notice: ' + JSON.stringify(backupNotice));
    this.noticeBoard.deleteNotice(notice.id);
  } else {
    this._cleanBackup(notice.data.backupId);
  }
};

ExtBackup.prototype.finishBackup = function (cb) {
  cb = cb || function() {};
  var backupNotice = lodash.findWhere(this.noticeBoard.notices, {type: 'backupInProgress'});
  if (!backupNotice) return cb(new Error('No backup notice'));
  var backupId = lodash.get(backupNotice, 'data.backupId');
  if (!backupId) {
    return console.error('Invalid Notice: ' + JSON.stringify(backupNotice));
  }
  this.noticeBoard.postNotice('backupDevCompleted', {backupId: backupId}, cb);
};

ExtBackup.prototype._handlerBackupDevCompleted = function (notice) {
  if (!notice.data || !notice.data.backupId)
    return console.error('Invalid Notice: ' + JSON.stringify(notice));
  var completed = this.noticeBoard.filterNotices({
    type: 'backupDevCompleted',
    data: {backupId: notice.data.backupId}
  });
  if (completed.length <= 1) return;
  if (completed[0].copayerId == completed[1].copayerId)
    return console.error('2 notices backupComplete from same device');
  this.noticeBoard.postNotice('backupDone', null);
};

ExtBackup.prototype._handlerBackupDone = function (notice) {
  this._cleanBackup();
};

module.exports = ExtBackup;