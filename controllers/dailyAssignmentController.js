const DailyAssignment = require('../models/dailyAssignmentModel');

const createDailyAssignment = (req, res) => {
  const formData = req.body;
  const dailyAssignment = new DailyAssignment(formData);
  dailyAssignment.save().then(() => console.log('Daily assignment saved to the database'));
  console.log('Received daily assignment data:', formData);
  res.json({ message: 'Daily assignment data received successfully on the server!' });
};

const getAllDailyAssignments = async (req, res) => {
  try {
    const dailyAssignments = await DailyAssignment.find();
    res.json(dailyAssignments);
  } catch (error) {
    console.error('Error fetching daily assignments:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

const deleteDailyAssignment = async (req, res) => {
  const assignmentId = req.params.id;
  try {
    await DailyAssignment.findOneAndDelete({ _id: assignmentId });
    res.json({ message: 'Daily assignment deleted successfully!' });
  } catch (error) {
    console.error('Error deleting daily assignment:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

const updateDailyAssignment = async (req, res) => {
  const assignmentId = req.params.id;
  const updatedData = req.body;
  try {
    const updatedAssignment = await DailyAssignment.findByIdAndUpdate(assignmentId, updatedData, { new: true });
    res.json(updatedAssignment);
  } catch (error) {
    console.error('Error updating daily assignment:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

module.exports = {
  createDailyAssignment,
  getAllDailyAssignments,
  deleteDailyAssignment,
  updateDailyAssignment,
};
