const express = require('express');
const router = express.Router();
const bankController = require('../controllers/bankController');

router.post('/', bankController.createBank);
router.get('/', bankController.getAllBanks);
router.delete('/:id', bankController.deleteBank);
router.put('/:id', bankController.updateBank);

module.exports = router;
