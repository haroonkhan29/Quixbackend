const Developer = require('../models/developerModel');

const createDeveloper = (req, res) => {
  const formData = req.body;
  const developer = new Developer(formData);
  
  developer.save().then(() => console.log('Developer data saved to the database'));
  console.log('Received developer data:', formData);
  
  res.json({ message: 'Developer data received successfully on the server!' });
};

const getAllDevelopers = async (req, res) => {
  try {
    const developers = await Developer.find();
    res.json(developers);
  } catch (error) {
    console.error('Error fetching developers:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

const deleteDeveloper = async (req, res) => {
  const developerId = req.params.id;
  try {
    await Developer.findOneAndDelete({ _id: developerId });
    res.json({ message: 'Developer deleted successfully!' });
  } catch (error) {
    console.error('Error deleting developer:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

const updateDeveloper = async (req, res) => {
  const developerId = req.params.id;
  const updatedData = req.body;
  
  try {
    const updatedDeveloper = await Developer.findByIdAndUpdate(developerId, updatedData, { new: true });
    res.json(updatedDeveloper);
  } catch (error) {
    console.error('Error updating developer:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

module.exports = {
  createDeveloper,
  getAllDevelopers,
  deleteDeveloper,
  updateDeveloper,
};
