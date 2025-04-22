const sequelize = require('../config/db');
const User = require('./User');
const Booking = require('./Booking');

(async () => {
  try {
    await sequelize.authenticate();
    console.log('✅ Database connected...');

    await sequelize.sync(); // creates tables
    console.log('✅ All models synced...');
  } catch (error) {
    console.error('❌ DB Connection Error:', error);
  }
})();

module.exports = { sequelize, User, Booking };
