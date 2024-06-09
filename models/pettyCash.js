const mongoose = require('mongoose');

const pettyCashSchema = new mongoose.Schema({
  date: String,
  expenseDescription: String,
  remarks: String,
  quantity: String,
  cashIn: String,
  cashOut: String,
  image: String,
});

const PettyCash = mongoose.model('PettyCash', pettyCashSchema);

module.exports = PettyCash;
