const mongoose = require('mongoose');
const Project = mongoose.model('Project', {
  name: String,
});

const createProject = (req, res) => {
  const formData = req.body;
  const project = new Project(formData);
  project.save().then(() => console.log('Project data saved to the database'));
  console.log('Received project data:', formData);
  res.json({ message: 'Project data received successfully on the server!' });
};

const getAllProjects = async (req, res) => {
  try {
    const projectDetails = await Project.find();
    res.json(projectDetails);
  } catch (error) {
    console.error('Error fetching project details:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

const deleteProject = async (req, res) => {
  const projectId = req.params.id;
  try {
    await Project.findOneAndDelete({ _id: projectId });
    res.json({ message: 'Project record deleted successfully!' });
  } catch (error) {
    console.error('Error deleting project record:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

const updateProject = async (req, res) => {
  const projectId = req.params.id;
  const updatedData = req.body;
  try {
    const updatedProject = await Project.findByIdAndUpdate(projectId, updatedData, { new: true });
    res.json(updatedProject);
  } catch (error) {
    console.error('Error updating project record:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

module.exports = {
  createProject,
  getAllProjects,
  deleteProject,
  updateProject,
};
