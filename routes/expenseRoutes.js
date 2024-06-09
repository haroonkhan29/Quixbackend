const express = require('express');
const router = express.Router();
const expenseController = require('../controllers/expenseController');

router.post('/', expenseController.addOrUpdateExpense);
router.get('/', expenseController.getExpenseByCategory);

  
module.exports = router;
