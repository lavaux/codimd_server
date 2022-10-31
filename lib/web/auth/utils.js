'use strict'

const models = require('../../models')
const logger = require('../../logger')

exports.passportGeneralCallback = async function callback (accessToken, refreshToken, profile, done) {
  const stringifiedProfile = JSON.stringify(profile)
  const args = {
    where: {
      profileid: profile.id.toString()
    },
    defaults: {
      profile: stringifiedProfile,
      accessToken,
      refreshToken
    }
  }
  try {
    let user = await models.User.findOne(args)
    let created = false
    if (!user) {
      if (profile.workspaces && profile.workspaces.indexOf('aquila-consortium') !== -1) {
        // Create a new user
        [user, created] = await models.User.findOrCreate(args)
      } else {
        logger.error('user ' + profile.id + ' not found')
        logger.error('content is ' + profile.email)
        return done(null, false)
      }
    }

    if (user && created) {
      logger.info('user ' + profile.id + ' created')
    }

    if (user) {
      let needSave = false
      if (user.profile !== stringifiedProfile) {
        user.profile = stringifiedProfile
        needSave = true
      }
      if (user.accessToken !== accessToken) {
        user.accessToken = accessToken
        needSave = true
      }
      if (user.refreshToken !== refreshToken) {
        user.refreshToken = refreshToken
        needSave = true
      }
      if (needSave) {
        user.save().then(function () {
          logger.debug(`user login: ${user.id}`)
          return done(null, user)
        })
      } else {
        logger.debug(`user login: ${user.id}`)
        return done(null, user)
      }
    }
  } catch (err) {
    logger.error('auth callback failed: ' + err)
    return done(err, null)
  }
}
