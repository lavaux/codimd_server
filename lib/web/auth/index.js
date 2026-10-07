'use strict'

const Router = require('express').Router
const passport = require('passport')

const config = require('../../config')
const logger = require('../../logger')
const models = require('../../models')

const authRouter = module.exports = Router()

const oauth2Auth = config.isOAuth2Enable ? require('./oauth2') : null

function isOAuth2User (user) {
  try {
    return JSON.parse(user.profile).provider === 'oauth2'
  } catch (err) {
    return false
  }
}

// only users who logged in through OAuth2 and are still in the workspace
// keep their session
function isSessionAllowed (user) {
  if (!oauth2Auth || !isOAuth2User(user)) return Promise.resolve(false)
  return oauth2Auth.isStillMember(user)
}

// serialize and deserialize
passport.serializeUser(function (user, done) {
  logger.info('serializeUser: ' + user.id)
  return done(null, user.id)
})

passport.deserializeUser(function (id, done) {
  models.User.findOne({
    where: {
      id
    }
  }).then(function (user) {
    // Don't die on non-existent user
    if (user == null) {
      return done(null, false, { message: 'Invalid UserID' })
    }

    return isSessionAllowed(user).then(function (allowed) {
      if (!allowed) {
        logger.info('deserializeUser: session of user ' + user.id + ' is no longer allowed')
        return done(null, false)
      }
      logger.info('deserializeUser: ' + user.id)
      return done(null, user)
    })
  }).catch(function (err) {
    logger.error(err)
    return done(err, null)
  })
})

if (config.isFacebookEnable) authRouter.use(require('./facebook'))
if (config.isTwitterEnable) authRouter.use(require('./twitter'))
if (config.isGitHubEnable) authRouter.use(require('./github'))
if (config.isGitLabEnable) authRouter.use(require('./gitlab'))
if (config.isMattermostEnable) authRouter.use(require('./mattermost'))
if (config.isDropboxEnable) authRouter.use(require('./dropbox'))
if (config.isGoogleEnable) authRouter.use(require('./google'))
if (config.isLDAPEnable) authRouter.use(require('./ldap'))
if (config.isSAMLEnable) authRouter.use(require('./saml'))
if (oauth2Auth) authRouter.use(oauth2Auth)
if (config.isEmailEnable) authRouter.use(require('./email'))
if (config.isOpenIDEnable) authRouter.use(require('./openid'))

// logout
authRouter.get('/logout', function (req, res) {
  if (config.debug && req.isAuthenticated()) {
    logger.debug('user logout: ' + req.user.id)
  }
  req.logout(() => {
    res.redirect(config.serverURL + '/')
  })
})
