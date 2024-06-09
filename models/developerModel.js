const mongoose = require('mongoose');

const Developer = mongoose.model('Developer', {
  name: String,
});

module.exports = Developer;
