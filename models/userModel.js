const mongoose = require('mongoose');

const User = mongoose.model('User', {
  username: String,
  email: String,
  password: String,
  resetToken: String,
  resetTokenExpiration: Date,
});

module.exports = User;