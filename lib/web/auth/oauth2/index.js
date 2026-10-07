'use strict'

const Router = require('express').Router
const passport = require('passport')
const { Strategy, InternalOAuthError } = require('passport-oauth2')
const config = require('../../../config')
const logger = require('../../../logger')
const { passportGeneralCallback } = require('../utils')
const { checkWorkspaceMembership } = require('./workspace')
const { createMembershipChecker } = require('./recheck')

const oauth2Auth = module.exports = Router()

class OAuth2CustomStrategy extends Strategy {
  constructor (options, verify) {
    options.customHeaders = options.customHeaders || {}
    super(options, verify)
    this.name = 'oauth2'
    this._userProfileURL = options.userProfileURL
    this._workspaceURL = options.workspaceURL
    this._oauth2.useAuthorizationHeaderforGET(true)
  }

  userProfile (accessToken, done) {
    const self = this
    self._oauth2.get(self._userProfileURL, accessToken, function (err, body, res) {
      let json, profile

      if (err) {
        return done(new InternalOAuthError('Failed to fetch user profile', err))
      }

      try {
        json = JSON.parse(body)
      } catch (ex) {
        return done(new Error('Failed to parse user profile'))
      }

      if (!checkAuthorization(json)) {
        return done('Permission denied', null)
      }

      try {
        profile = parseProfile(json)
      } catch (ex) {
        return done('Failed to identify user profile information', null)
      }
      profile.provider = 'oauth2'

      if (!config.oauth2.workspace) {
        return done(null, profile)
      }

      checkWorkspaceMembership(self._oauth2, accessToken, self._workspaceURL, config.oauth2.workspace, function (err, isMember) {
        if (err) {
          logger.warn(`oauth2: failed to check workspace membership of user "${profile.username}": ${err.message || JSON.stringify(err)}`)
          return done('Permission denied', null)
        }
        if (!isMember) {
          logger.debug(`oauth2: user "${profile.username}" is not a member of workspace "${config.oauth2.workspace}". Permission denied`)
          return done('Permission denied', null)
        }
        done(null, profile)
      })
    })
  }
}

function extractProfileAttribute (data, path) {
  // can handle stuff like `attrs[0].name`
  path = path.split('.')
  for (const segment of path) {
    const m = segment.match(/([\d\w]+)\[(.*)\]/)
    data = m ? data[m[1]][m[2]] : data[segment]
  }
  return data
}

function parseProfile (data) {
  // only try to parse the id if a claim is configured
  const id = config.oauth2.userProfileIdAttr ? extractProfileAttribute(data, config.oauth2.userProfileIdAttr) : undefined
  const username = extractProfileAttribute(data, config.oauth2.userProfileUsernameAttr)
  const displayName = extractProfileAttribute(data, config.oauth2.userProfileDisplayNameAttr)
  const email = extractProfileAttribute(data, config.oauth2.userProfileEmailAttr)

  if (id === undefined && username === undefined) {
    logger.error('oauth2 auth failed: id and username are undefined')
    throw new Error('User ID or Username required')
  }

  return {
    id: id || username,
    username,
    displayName,
    emails: email ? [email] : []
  }
}

// returns true if the user may log in according to the accessRole setting
function checkAuthorization (data) {
  // a role the user must have is set in the config
  if (config.oauth2.accessRole) {
    // check if we know which claim contains the list of groups a user is in
    if (!config.oauth2.rolesClaim) {
      // log error, but accept all logins
      logger.error('oauth2: "accessRole" is configured, but "rolesClaim" is missing from the config. Can\'t check group membership!')
    } else {
      // parse and check role data
      let roles = []
      try {
        roles = extractProfileAttribute(data, config.oauth2.rolesClaim)
      } catch (err) {
        logger.warn(`oauth2: failed to extract rolesClaim '${config.oauth2.rolesClaim}' from user profile.`)
        return false
      }
      if (!roles) {
        logger.error('oauth2: "accessRole" is configured, but user profile doesn\'t contain roles attribute. Permission denied')
        return false
      }
      if (!roles.includes(config.oauth2.accessRole)) {
        const username = extractProfileAttribute(data, config.oauth2.userProfileUsernameAttr)
        logger.debug(`oauth2: user "${username}" doesn't have the required role. Permission denied`)
        return false
      }
    }
  }
  return true
}

const strategy = new OAuth2CustomStrategy({
  authorizationURL: config.oauth2.authorizationURL,
  tokenURL: config.oauth2.tokenURL,
  clientID: config.oauth2.clientID,
  clientSecret: config.oauth2.clientSecret,
  callbackURL: config.serverURL + '/auth/oauth2/callback',
  workspaceURL: config.oauth2.workspaceURL,
  userProfileURL: config.oauth2.userProfileURL,
  scope: config.oauth2.scope,
  pkce: config.oauth2.pkce,
  state: true
}, passportGeneralCallback)
passport.use(strategy)

// Resolves to false once a logged-in user has left the workspace.
// Without a configured workspace every user stays logged in.
oauth2Auth.isStillMember = config.oauth2.workspace
  ? createMembershipChecker({
    oauth2Client: strategy._oauth2,
    workspacesURL: config.oauth2.workspaceURL,
    workspace: config.oauth2.workspace,
    interval: config.oauth2.workspaceRecheckInterval,
    logger
  })
  : () => Promise.resolve(true)

oauth2Auth.get('/auth/oauth2', function (req, res, next) {
  passport.authenticate('oauth2')(req, res, next)
})

// github auth callback
oauth2Auth.get('/auth/oauth2/callback',
  passport.authenticate('oauth2', {
    successReturnToOrRedirect: config.serverURL + '/',
    failureRedirect: config.serverURL + '/'
  })
)
