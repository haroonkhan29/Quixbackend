const Progress = require('../models/expenseformModel');

const createExpense = (req, res) => {
  const formData = req.body;
  const progress = new Progress(formData);
  progress.save()
    .then(() => console.log('Progress data saved to the database'))
    .catch(error => {
      console.error('Error saving progress data:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    });
  console.log('Received progress data:', formData);
  res.json({ message: 'Progress data received successfully on the server!' });
};

const getAllExpense = async (req, res) => {
  try {
    const progressDetails = await Progress.find();
    res.json(progressDetails);
  } catch (error) {
    console.error('Error fetching progress details:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

const deleteExpense = async (req, res) => {
  const progressId = req.params.id;
  try {
    await Progress.findOneAndDelete({ _id: progressId });
    res.json({ message: 'Progress record deleted successfully!' });
  } catch (error) {
    console.error('Error deleting progress record:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

const updateExpense = async (req, res) => {
  const progressId = req.params.id;
  const updateData = req.body;
  try {
    const updatedProgress = await Progress.findByIdAndUpdate(progressId, updateData, { new: true });
    res.json(updatedProgress);
  } catch (error) {
    console.error('Error updating progress record:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

module.exports = {
  createExpense,
  getAllExpense,
  deleteExpense,
  updateExpense,
};
