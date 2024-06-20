'use strict';
/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('Sports', {
      id: {
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
        type: Sequelize.INTEGER
      },
      title: {
        type: Sequelize.STRING,
        allowNull:false,
        validate:{
          notNull:true,
        }
      },
      date: {
        type: Sequelize.DATEONLY,
        allowNull:false,
        validate:{
          notNull:true,
        }
      },
      time:{
        type: Sequelize.TIME,
        allowNull:false,
        validate:{
          notNull:true,
        }
      },
      players: {
        type: Sequelize.STRING,
      },
      location:{
        type: Sequelize.STRING,
        allowNull:false,
        validate:{
          notNull:true,
        }
      },
      additional:{
        type: Sequelize.INTEGER,
      },
      createdAt: {
        allowNull: false,
        type: Sequelize.DATE
      },
      updatedAt: {
        allowNull: false,
        type: Sequelize.DATE
      }
    });
  },
  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('Sports');
  }
};