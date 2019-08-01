import Sequelize from 'sequelize';

import sequelize from '../util/database';


const User = sequelize.define('user', {
  id: {
    type: Sequelize.INTEGER,
    autoIncrement: true,
    allowNull: false,
    primaryKey: true
  },
  name: Sequelize.STRING,
  email: Sequelize.STRING,
  password: Sequelize.STRING,
  country: Sequelize.STRING,
  birthday: Sequelize.DATEONLY,  
  resetToken:Sequelize.STRING,
  tokenExpiry: Sequelize.DATE,
  createdAt: Sequelize.DATE,
  updatedAt: Sequelize.DATE,
});

export default User;
