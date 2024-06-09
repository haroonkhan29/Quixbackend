const mongoose = require('mongoose');

const cashSchema = new mongoose.Schema({
  category: String,
  Jan: String,
  Feb: String,
  Mar: String,
  Apr: String,
  May: String,
  Jun: String,
  Jul: String,
  Aug: String,
  Sep: String,
  Oct: String,
  Nov: String,
  Dec: String
});

module.exports = mongoose.model('Cash', cashSchema);