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

/**
 * Delete notices concernig backups. Do not delete cancelBackup notices. backupDone notices will be deleted only if
 * timestamp is specified as parameter.
 *
 * @param opts.backupId If specified only related notices will be deleted
 * @param opts.timestamp If spcified and backupId is not specified, only the notices older than timestamp will be deleted
 * @param done
 * @private
 */
NoticeBoard.prototype._cleanBackup = function (opts, done) {
  var self = this;
  if (lodash.isFunction(opts)) {
    done = opts;
    opts = {};
  }
  opts = opts || {};
  var backupId = opts.backupId;
  var timestamp = opts.timestamp;  // timestamp is ignored if backupId is specified
  var toDelete = self.filterNotices(!backupId
    ? timestamp
      ? function (n) {
        return ((n.data && n.data.backupId) || n.type === 'backupDone') && n.timestamp < timestamp
          && n.type !== 'cancelBackup';
      }
      : function (n) {
        return n.data && n.data.backupId
          && n.type !== 'cancelBackup' && n.type !== 'backupDone';
      }
    : function (n) {
      return n.data && n.data.backupId && n.data.backupId === backupId
        && n.type !== 'cancelBackup' && n.type !== 'backupDone';
    }
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
      //TODO verificare: qui _cleanBackup() cancella tutti le notizie di backup, mentre la risposta al cancelBackup cancellerà solo quelle relative al backupId
      self._cleanBackup(done);
    }
  );
};

NoticeBoard.prototype._handlerCancelBackup = function (notice) {
  if (!notice.data || !notice.data.backupId || notice.type !== 'cancelBackup') {
    console.error('Invalid notice on _handlerCancelBackup(): ' + JSON.stringify(backupNotice));
    this.deleteNotice(notice.id);
    return;
  }
  this._cleanBackup(notice.data.backupId);
  if (notice.copayerId !== this.credentials.copayerId) {
    this.deleteNotice(notice.id);
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
  if (completed[0].copayerId === completed[1].copayerId) {
    //TODO una delle due sarebbe da eliminare
    return console.error('2 notices backupDevCompleted from same device');
  }
  this.postNotice('backupDone', null);
};

NoticeBoard.prototype._handlerBackupDone = function (notice) {
  this._cleanBackup({timestamp: notice.timestamp});
};
