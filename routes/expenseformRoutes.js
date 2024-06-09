const express = require('express');
const router = express.Router();
const expenseformController = require('../controllers/expenseformController');

router.post('/', expenseformController.createExpense);
router.get('/', expenseformController.getAllExpense);
router.delete('/:id', expenseformController.deleteExpense);
router.put('/:id', expenseformController.updateExpense); 

module.exports = router;
