const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const AdMob = require('../models/admobModel');


const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({ storage });

router.post('/', upload.single('profilePic'), async (req, res) => {
  try {
    const { date, accountName } = req.body;
    const profilePic = req.file ? req.file.filename : null;

    const newAdMob = new AdMob({
      date,
      accountName,
      profilePic,
    });

    const savedAdMob = await newAdMob.save();
    res.json(savedAdMob);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});


router.get('/', async (req, res) => {
  try {
    const admobData = await AdMob.find();
    res.json(admobData);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

router.put('/:id', upload.single('profilePic'), async (req, res) => {
  try {
    const { date, accountName } = req.body;
    const profilePic = req.file ? req.file.filename : null;

    const updatedAdMob = await AdMob.findByIdAndUpdate(
      req.params.id,
      { date, accountName, profilePic },
      { new: true }
    );

    res.json(updatedAdMob);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});
router.delete('/:id', async (req, res) => {
  try {
    const deletedAdMob = await AdMob.findByIdAndDelete(req.params.id);
    res.json(deletedAdMob);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

module.exports = router;
