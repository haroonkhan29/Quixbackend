const mongoose = require('mongoose');

const Attendance = mongoose.model('Attendance', {
    user_id: String,
    timestamp: String,
    status: String,
}
);
module.exports = Attendance;