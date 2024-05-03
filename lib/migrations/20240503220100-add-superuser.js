'use strict'
module.exports = {
  up: function (queryInterface, Sequelize) {
    return queryInterface.addColumn('Users', 'superuser', Sequelize.BOOLEAN)
  },

  down: function (queryInterface, Sequelize) {
    return queryInterface.removeColumn('Users', 'superuser');
  }
}
