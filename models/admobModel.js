const mongoose = require('mongoose');

const AdMob = mongoose.model('AdMob', {
  date: String,
  accountName: String,
  profilePic: String,
  
});


module.exports = AdMob;