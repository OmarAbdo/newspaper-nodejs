const Sequelize = require('sequelize');

const sequelize = new Sequelize('newspaper', 'root', '', {
  dialect: 'mysql',
  host: 'localhost'
});

module.exports = sequelize;
