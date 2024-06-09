const Attendance = require('../models/attendanceModel');
const Employee = require('../models/employeeModel');


const getAllAttendance = async (req, res) => {
  try {
    const employeeDetails = await Employee.find();
    const selectedDate = req.query.date || new Date().toISOString().split('T')[0];

    const currentDate = new Date().toISOString().split('T')[0];
    console.log(currentDate)
    const updatedEmployeeDetails = await Promise.all(employeeDetails.map(async (employee) => {
      const attendanceRecord = await Attendance.findOne({
        user_id: employee.id,
        timestamp: selectedDate
      });

      const status = attendanceRecord ? 'present' : 'absent';
      console.log(attendanceRecord)
      return {
        ...employee.toObject(),
        status,
        timestamp: selectedDate
      };
      
    }));
    res.json(updatedEmployeeDetails);
  } catch (error) {
    console.error('Error fetching employee details:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

module.exports = {
  getAllAttendance,
}
