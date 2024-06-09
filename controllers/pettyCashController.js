const PettyCash = require('../models/pettyCash');

exports.createPettyCash = async (req, res) => {
    try {
        const pettyCash = new PettyCash();

        if (req.body.date) pettyCash.date = req.body.date;
        if (req.body.expenseDescription) pettyCash.expenseDescription = req.body.expenseDescription;
        if (req.body.remarks) pettyCash.remarks = req.body.remarks;
        if (req.body.quantity) pettyCash.quantity = req.body.quantity;
        if (req.body.cashIn) pettyCash.cashIn = req.body.cashIn;
        if (req.body.cashOut) pettyCash.cashOut = req.body.cashOut;
        if (req.file) pettyCash.image = req.file.path;

        await pettyCash.save();
        res.status(201).json(pettyCash);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
};

exports.getPettyCash = async (req, res) => {
    try {
        const pettyCash = await PettyCash.find();
        res.json(pettyCash);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
};

exports.updatePettyCash = async (req, res) => {
    try {
        const { id } = req.params;
        let imagePath = ''; 
        if (req.file) {
            imagePath = "uploads/" + req.file.filename;
        }

        const updatedFields = {
            ...req.body, 
            image: req.file ? imagePath : req.body.image 
        };

        const pettyCash = await PettyCash.findByIdAndUpdate(id, updatedFields, { new: true });

        if (!pettyCash) {
            return res.status(404).json({ message: 'Petty cash record not found' });
        }

        res.json(pettyCash);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
};

exports.deletePettyCash = async (req, res) => {
    try {
      const { id } = req.params;
      const pettyCash = await PettyCash.findByIdAndDelete(id);
  
      if (!pettyCash) {
        return res.status(404).json({ message: 'Petty cash record not found' });
      }
  
      res.json({ message: 'Petty cash record deleted successfully' });
    } catch (err) {
      res.status(500).json({ message: err.message });
    }
  };