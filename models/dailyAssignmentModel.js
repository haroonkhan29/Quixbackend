const mongoose = require('mongoose');

const DailyAssignment = mongoose.model('DailyAssignment', {
  account: String,
  date: Date,
  project: String,
  developer: String,
  status: String,
  task: String,
  deadline: Date,
});

module.exports = DailyAssignment;
