const express = require('express');
const router = express.Router();
const progressController = require('../controllers/progressController');

router.post('/', progressController.createProgress);
router.get('/', progressController.getAllProgress);
router.delete('/:id', progressController.deleteProgress);
router.put('/:id', progressController.updateProgress); 

module.exports = router;
