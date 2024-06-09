const mongoose = require('mongoose');

const Progress = mongoose.model('Progress', {
  googleappPublishedDate: String,
  googleAccount: String,
  googleTotalInstalls: String,
  googleTotalUninstalls: String,
  googletotalUserLoss: String,
  googleConversionRate: String,
  googleApps: String,
  gameappPublishedDate: String,
  gameAccount: String,
  gameTotalInstalls: String,
  gameTotalUninstalls: String,
  gametotalUserLoss: String,
  gameConversionRate: String,
  gameApps: String,
  iOSappPublishedDate: String,
  iOSAccount: String,
  iOSTotalInstalls: String,
  iOSTotalUninstalls: String,
  iOStotalUserLoss: String,
  iOSConversionRate: String,
  iOSApps: String,
});

module.exports = Progress;
