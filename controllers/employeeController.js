const path = require('path');
const Employee = require('../models/employeeModel');
const createEmployee = (req, res) => {
  const formData = req.body;
  if (req.file) {
    console.log("File received:", req.file.originalname);
    const extname = path.extname(req.file.originalname);
    formData.profilePic = req.file.filename;  
  } else {
    console.log("No file received");

  }

  const employee = new Employee(formData);

  employee.save()
    .then(() => {
      console.log('Employee data saved to the database');
      res.json({ message: 'Employee data received successfully on the server!' });
    })
    .catch((error) => {
      console.error('Error saving employee data:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    });
};

const getAllEmployees = async (req, res) => {
  try {
    const employeeDetails = await Employee.find();
    res.json(employeeDetails);
  } catch (error) {
    console.error('Error fetching employee details:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

const deleteEmployee = async (req, res) => {
  const employeeId = req.params.id;
  try {
    await Employee.findOneAndDelete({ _id: employeeId });
    res.json({ message: 'Employee deleted successfully!' });
  } catch (error) {
    console.error('Error deleting employee:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

const updateEmployee = async (req, res) => {
  const employeeId = req.params.id;
  const updatedData = JSON.parse(req.body.data);

  if (req.file) {
    updatedData.profilePic = req.file.filename;
  }

  try {
    const updatedEmployee = await Employee.findByIdAndUpdate(employeeId, updatedData, { new: true });
    res.json(updatedEmployee);
  } catch (error) {
    console.error('Error updating employee:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

module.exports = {
  createEmployee,
  getAllEmployees,
  deleteEmployee,
  updateEmployee,
};
