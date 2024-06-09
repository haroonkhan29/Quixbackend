const mongoose = require('mongoose');

const Bank = mongoose.model('Bank', {
  bank: String,
  google: String,
  accountNumber: String,
  accountTitle: String,
  bankAddress: String,
  card: String,
  cvv: String,
  expiryDate: String,
});

module.exports = Bank;
