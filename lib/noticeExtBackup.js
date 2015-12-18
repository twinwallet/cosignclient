'use strict';

var lodash = require('lodash');
var async = require('async');
var NoticeBoard = require('./noticeBoard');

NoticeBoard.prototype.initExtBackup = function () {
  this.on('newNotice/cancelBackup', NoticeBoard.prototype._handlerCancelBackup.bind(this));
  this.on('newNotice/backupDevCompleted', NoticeBoard.prototype._handlerBackupDevCompleted.bind(this));
  this.on('newNotice/backupDone', NoticeBoard.prototype._handlerBackupDone.bind(this));
  return this; //useful for chaining
};

NoticeBoard.prototype.startBackup = function (cb) {
  var backupId = Math.random().toString(36).substring(8);
  this.postNotice('backupInProgress', {backupId: backupId}, cb);
};

NoticeBoard.prototype._cleanBackup = function (backupId, done) {
  if (lodash.isFunction(backupId)) {
    done = backupId;
    backupId = null;
  }
  var self = this;
  var toDelete = self.filterNotices(
    !backupId ? function (n) {
      return n.data && n.data.backupId
        && n.type !== 'cancelBackup' && n.type !== 'backupDone';
    }
      :
    {data: {backupId: backupId}}
  );
  async.each(toDelete,
    function (n, cb) {
      self.deleteNotice(n.id, cb);
    },
    function() { if (done) done(); }
  );
};

NoticeBoard.prototype.cancelBackup = function (done) {
  var self = this;
  async.each(self.filterNotices({type: 'backupInProgress'}),
    function (n, cb) {
      self.postNotice('cancelBackup', {backupId: n.data.backupId}, cb);
    },
    function (err) {
      if (err) return done(err);
      self._cleanBackup(done);
    }
  );
};

NoticeBoard.prototype._handlerCancelBackup = function (notice) {
  if (notice.copayerId === this.credentials.copayerId) return;
  if (!notice.data || !notice.data.backupId) {
    console.error('Invalid Notice: ' + JSON.stringify(backupNotice));
    this.deleteNotice(notice.id);
  } else {
    this._cleanBackup(notice.data.backupId);
  }
};

NoticeBoard.prototype.finishBackup = function (cb) {
  cb = cb || function() {};
  var backupNotice = lodash.findWhere(this.notices, {type: 'backupInProgress'});
  if (!backupNotice) return cb(new Error('No backup notice'));
  var backupId = lodash.get(backupNotice, 'data.backupId');
  if (!backupId) {
    return console.error('Invalid Notice: ' + JSON.stringify(backupNotice));
  }
  this.postNotice('backupDevCompleted', {backupId: backupId}, cb);
};

NoticeBoard.prototype._handlerBackupDevCompleted = function (notice) {
  if (!notice.data || !notice.data.backupId)
    return console.error('Invalid Notice: ' + JSON.stringify(notice));
  var completed = this.filterNotices({
    type: 'backupDevCompleted',
    data: {backupId: notice.data.backupId}
  });
  if (completed.length <= 1) return;
  if (completed[0].copayerId == completed[1].copayerId)
    return console.error('2 notices backupComplete from same device');
  this.postNotice('backupDone', null);
};

NoticeBoard.prototype._handlerBackupDone = function (notice) {
  this._cleanBackup();
};
