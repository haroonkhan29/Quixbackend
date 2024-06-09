const express = require('express');
const router = express.Router();
const inventoryController = require('../controllers/inventoryController');

router.post('/', inventoryController.createInventory);
router.get('/', inventoryController.getAllInventory);
router.delete('/:id', inventoryController.deleteInventory);
router.put('/:id', inventoryController.updateInventory); 

module.exports = router;
