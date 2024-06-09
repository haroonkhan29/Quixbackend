const express = require('express');
const router = express.Router();
const expenseController2 = require('../controllers/expenseController2'); 

router.post('/', expenseController2.addOrUpdateExpense2);
router.get('/', expenseController2.getExpenseByCategory2);

module.exports = router;
