const express = require('express');
const router = express.Router();
const employeeController = require('../controllers/employeeController');
const multer = require('multer');
const path = require('path'); 

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/'); 
  },
  filename: function (req, file, cb) {
    const extname = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + Date.now() + extname);
  },
});

const upload = multer({ storage: storage });
router.post('/', upload.single('profilePic'), employeeController.createEmployee);
router.get('/', employeeController.getAllEmployees);
router.delete('/:id', employeeController.deleteEmployee);
router.put('/:id', upload.single('profilePic'), employeeController.updateEmployee);


module.exports = router;
