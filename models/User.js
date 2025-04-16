const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email:    { type: String, required: true, unique: true },
  password: { type: String, required: true },
  dob:      { type: Date, required: true },
  address:  { type: String, required: true },
  sex:      { type: String, enum: ['Male', 'Female', 'Other'], required: true }
});

module.exports = mongoose.model('User', userSchema);
