const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const mongoose = require('mongoose');
const bankRoutes = require('./routes/bankRoutes');
const employeeRoutes = require('./routes/employeeRoutes');
const attendanceRoutes = require('./routes/attendanceRoutes');
const userRoutes = require('./routes/userRoutes');
const admobRoutes = require('./routes/admobRoutes');
const dailyAssignmentRoutes = require('./routes/dailyAssignmentRoutes');
const progressRoutes = require('./routes/progressRoutes');
const developerRoutes = require('./routes/developerRoutes');
const projectRoutes = require('./routes/projectRoutes');
const expenseformRoutes = require('./routes/expenseformRoutes');
const expensesheetformRoutes = require('./routes/expensesheetformRoutes');
const expenseRoutes = require('./routes/expenseRoutes');
const expenseSheet2 = require('./routes/expenseSheet2');
const pettyCashRoutes = require('./routes/pettyCashRoutes');
const inventoryRoutes = require('./routes/inventoryRoutes');

const app = express();
const port = 3001;

app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// Replace 'username' and 'password' with your MongoDB credentials
mongoose.connect('mongodb://admin2:admin2@localhost:27017/quix-db?authSource=admin', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

app.use('/bank', bankRoutes);
app.use('/employee', employeeRoutes);
app.use('/attendance', attendanceRoutes);
app.use('/user', userRoutes);
app.use('/dailyAssignment', dailyAssignmentRoutes);
app.use('/expenseform',  expenseformRoutes);
app.use('/expensesheet',  expensesheetformRoutes);
app.use('/progress', progressRoutes);
app.use('/developer', developerRoutes);
app.use('/project', projectRoutes);
app.use('/admob', admobRoutes);
app.use('/expenses', expenseRoutes);
app.use('/cash', expenseSheet2);
app.use('/pettycash', pettyCashRoutes);
app.use('/inventory', inventoryRoutes);

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
