const Bank = require('../models/bankModel');
const createBank = (req, res) => {
  const formData = req.body;
  const bank = new Bank(formData);
  bank.save().then(() => console.log('Bank data saved to the database'));
  console.log('Received bank data:', formData);
  res.json({ message: 'Bank data received successfully on the server!' });
};
const getAllBanks = async (req, res) => {
  try {
    const bankDetails = await Bank.find();
    res.json(bankDetails);
  } catch (error) {
    console.error('Error fetching bank details:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

const deleteBank = async (req, res) => {
  const bankId = req.params.id;
  try {
    await Bank.findOneAndDelete({ _id: bankId });
    res.json({ message: 'Bank record deleted successfully!' });
  } catch (error) {
    console.error('Error deleting bank record:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

const updateBank = async (req, res) => {
  const bankId = req.params.id;
  const updatedData = req.body;
  try {
    const updatedBank = await Bank.findByIdAndUpdate(bankId, updatedData, { new: true });
    res.json(updatedBank);
  } catch (error) {
    console.error('Error updating bank record:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

module.exports = {
  createBank,
  getAllBanks,
  deleteBank,
  updateBank,
};
