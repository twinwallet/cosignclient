'use strict';

var _ = require('lodash');
var BWClient = require('bitcore-wallet-client');

var MOCKS = module.exports = {};

var clients = [
  'tprv8ZgxMBicQKsPfB68j6QH2jhxju935kx7eXqg28aMBD49wd7Crrqwv665r7ikjeMH8N1jb25J45LhTm7FwhqNRHp7Ddy6CcVfYpHW73zAdvP',
  'tprv8ZgxMBicQKsPe4EpMwgKFqMmJVqY4tPJdhRzZCx8hm9EaDUAw83Z5YazrVKriSDu1QTkf1GjFaFNB8maXYULooG8WeB2frrxsrEYUWq4hGZ',
  'tprv8ZgxMBicQKsPdM28UpEyZoTmYiGjELD2H4WyFQeBxsd2WZYopc5zsdPf2ZZkWbNULfd5aXKvxiNhrvkAxLAoWwBDbWx4CNQaCDAFA3DzK1g'
].map(function (xpk) {
  var client = new BWClient();
  client.seedFromExtendedPrivateKey(xpk);
  client.credentials.addWalletInfo(
    '7c9a7df9-990c-4de6-8f49-572ff0938216',
    'prova 1 testnet 2su3',
    2,
    3,
    '4e58ac54ff84baa013d71ccfd70f4765dfd15d85da9e189d5c1f94510e2b4b08',
    'primo'
  );
  return client;
});
var pkr = clients.map(function (c) {
  return {
    requestPubKey: c.requestPubKey,
    xPubKey: c.xPubKey
  };
});
clients.forEach(function (c) {
  c.credentials.addPublicKeyRing(pkr);
});

MOCKS.CLIENTS = _.clone(clients, true);
//MOCKS.FOCUSEDWALLETID = focusedId;

MOCKS.REQUEST_NULL = function() { return { then: function(s, e) {} } };