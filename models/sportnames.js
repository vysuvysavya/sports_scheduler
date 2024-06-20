'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class Sportname extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      Sportname.belongsTo(models.User,{
        foreignKey:'userId',
      })
      // define association here
    }
  }
  Sportname.init({
    title: DataTypes.STRING
  }, {
    sequelize,
    modelName: 'Sportname',
  });
  return Sportname;
};