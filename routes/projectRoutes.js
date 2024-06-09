const express = require('express');
const router = express.Router();
const projectController = require('../controllers/projectController');

router.post('/create', projectController.createProject);
router.get('/getAll', projectController.getAllProjects);
router.delete('/:id', projectController.deleteProject);
router.put('/:id', projectController.updateProject);

module.exports = router;
