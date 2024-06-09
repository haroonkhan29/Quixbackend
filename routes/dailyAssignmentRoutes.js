const express = require('express');
const dailyAssignmentController = require('../controllers/dailyAssignmentController');

const router = express.Router();

router.post('/create', dailyAssignmentController.createDailyAssignment);
router.get('/getAll', dailyAssignmentController.getAllDailyAssignments);
router.delete('/:id', dailyAssignmentController.deleteDailyAssignment);
router.put('/:id', dailyAssignmentController.updateDailyAssignment);

module.exports = router;
