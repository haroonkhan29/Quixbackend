const mongoose = require('mongoose');

const Project = mongoose.model('Project', {
  name: String,
});

module.exports = Project;
