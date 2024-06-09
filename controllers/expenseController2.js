const Expense = require('../models/ExpenseSheet');

const addOrUpdateExpense2 = async (req, res) => {
  try {
    const { category, month, value } = req.body;
    let expense = await Expense.findOne({ category });

    if (expense) {
      expense[month] = value;
    } else {
      expense = new Expense({ category });
      expense[month] = value;
    }

    await expense.save();
    res.status(201).json({ message: 'Expense updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const getExpenseByCategory2 = async (req, res) => {
  const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  try {
    const { category } = req.query;
    const expenses = await Expense.find({});
  
    if (!expenses) {
      return res.status(404).json({ message: 'Expense not found for this category' });
    }
  
    const sortedExpenses = expenses.map(expense => {
      const sortedExpense = {
        category: expense.category
      };
  
      MONTHS.forEach(month => {
        sortedExpense[month] = expense[month] || '0';
      });
  
      return sortedExpense;
    });
  
    res.status(200).json(sortedExpenses);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

module.exports = { addOrUpdateExpense2, getExpenseByCategory2 };
