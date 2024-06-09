const mongoose = require('mongoose');

const expenseSchema = new mongoose.Schema({
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

module.exports = mongoose.model('Expense', expenseSchema);
