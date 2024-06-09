const mongoose = require('mongoose');

const Inventory = mongoose.model('Inventory', {
  sNo: String,
  item: String,
  secondIMEI: String,
  brand: String,
  modelNo: String,
  deviceVersion: String,
  iMEI: String,
  issuedTo: String,
  qty: String,
  comments: String,
  // ledsNo: String,
  // ledItem: String,
  // ledBrand: String,
  // ledmodelNo: String,
  // ledVersion: String,
  // ledAccessories: String,
  // ledLocation: String,
  // ledQty: String,
  // ledComments: String,
//   iOSTotalInstalls: String,
//   iOSTotalUninstalls: String,
//   iOStotalUserLoss: String,
//   iOSConversionRate: String,
//   iOSApps: String,
});

module.exports = Inventory;
