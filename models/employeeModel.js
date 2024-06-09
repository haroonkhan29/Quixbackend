const mongoose = require('mongoose');

const Employee = mongoose.model('Employee', {
  profilePic: String,
  id: String,
  status: String,
  fullName: String,
  email: String,
  dob: String,
  joining: String,
  leavingDate: String,
  department: String,
  tittle: String,
  cnic: String,
  account: String,
  salary: String,
  gender: String,
  contact: String,
  addressCity: String,
  addressPostalCode: String,
});

module.exports = Employee;
