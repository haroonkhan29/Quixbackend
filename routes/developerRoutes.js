const express = require('express');
const router = express.Router();
const developerController = require('../controllers/developerController');

router.post('/create', developerController.createDeveloper);
router.get('/getAll', developerController.getAllDevelopers);
router.delete('/:id', developerController.deleteDeveloper);
router.put('/:id', developerController.updateDeveloper);

module.exports = router;
