'use strict'
module.exports = {
  up: async function (queryInterface, Sequelize) {
    await queryInterface.addColumn('Users', 'apiTokenHash', Sequelize.STRING(64))
    await queryInterface.addColumn('Users', 'apiTokenCreatedAt', Sequelize.DATE)
    await queryInterface.addColumn('Users', 'apiTokenLastUsedAt', Sequelize.DATE)
    await queryInterface.addIndex('Users', ['apiTokenHash'], { name: 'users_api_token_hash', unique: true })
  },

  down: async function (queryInterface, Sequelize) {
    await queryInterface.removeIndex('Users', 'users_api_token_hash')
    await queryInterface.removeColumn('Users', 'apiTokenLastUsedAt')
    await queryInterface.removeColumn('Users', 'apiTokenCreatedAt')
    await queryInterface.removeColumn('Users', 'apiTokenHash')
  }
}
