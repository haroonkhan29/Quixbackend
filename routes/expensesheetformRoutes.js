const express = require('express');
const router = express.Router();
const expensesheetformController = require('../controllers/expensesheetformController');

router.post('/', expensesheetformController.createExpenseSheet);
router.get('/', expensesheetformController.getAllExpenseSheet);
router.delete('/:id', expensesheetformController.deleteExpenseSheet);
router.put('/:id', expensesheetformController.updateExpenseSheet); 

module.exports = router;
