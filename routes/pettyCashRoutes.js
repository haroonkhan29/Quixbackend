// pettyCashRoutes.js

const express = require('express');
const router = express.Router();
const pettyCashController = require('../controllers/pettyCashController');
const multer = require('multer');

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname);
    }
});
const upload = multer({ storage: storage });

router.post('/', upload.single('image'), pettyCashController.createPettyCash);
router.get('/', pettyCashController.getPettyCash);
router.put('/:id',upload.single('image'), pettyCashController.updatePettyCash);
router.delete('/:id', pettyCashController.deletePettyCash);

module.exports = router;
