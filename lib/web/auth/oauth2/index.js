'use strict'

const Router = require('express').Router
const passport = require('passport')
const { Strategy, InternalOAuthError } = require('passport-oauth2')
const config = require('../../../config')
const logger = require('../../../logger')
const { passportGeneralCallback } = require('../utils')

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
      let json

      if (err) {
        return done(new InternalOAuthError('Failed to fetch user profile', err))
      }

      try {
        json = JSON.parse(body)
      } catch (ex) {
        return done(new Error('Failed to parse user profile'))
      }

      checkAuthorization(json, done)

      self._oauth2.get(self._workspaceURL, accessToken, function (errW, bodyW, resW) {
        let jsonW

        if (errW) {
          return done(new InternalOAuthError('Failed to fetch workspace profile', errW))
        }

        try {
          jsonW = JSON.parse(bodyW)
        } catch (ex) {
          return done(new Error('Failed to parse workspace profile'))
        }

        parseProfile(json, jsonW, (url,cb)=>{
          self._oauth2.get(url, accessToken, (errW_2, bodyW_2, resW_2)=>{
            let jsonW_2

            if (errW_2) {
              return done(new InternalOAuthError('Failed to fetch workspace profile while paginating', errW_2))
            }

            try {
              jsonW_2 = JSON.parse(bodyW_2)
            } catch (ex) {
              return done(new Error('Failed to parse workspace profile while paginating'))
            }
            cb(jsonW_2)
          })
        }, (profile)=>{
          profile.provider = 'oauth2'
          done(null, profile)
        })
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

function parseProfile (data, dataWorkspace, get_next, done_parse) {
  // only try to parse the id if a claim is configured
  const id = config.oauth2.userProfileIdAttr ? extractProfileAttribute(data, config.oauth2.userProfileIdAttr) : undefined
  const username = extractProfileAttribute(data, config.oauth2.userProfileUsernameAttr)
  const displayName = extractProfileAttribute(data, config.oauth2.userProfileDisplayNameAttr)
  const email = extractProfileAttribute(data, config.oauth2.userProfileEmailAttr)
  const newWorkspace = []

  let analyzeData = function(data, start) {
    const workspaces = data.values

    if (start)
       logger.info('workspaces are: ')
    for (const element of workspaces) {
      newWorkspace.push(element.slug)
      logger.info(' ' + element.slug)
    }
    if (data.next) {
      logger.info("Next page is " + data.next)
      get_next(data.next, analyzeData)
      return
    }
    logger.info('done workspaces...')
    done_parse({
      id: id || username,
      username: username,
      displayName: displayName,
      emails: email ? [email] : [],
      workspaces: newWorkspace
    })
  }
  analyzeData(dataWorkspace, true)
}

function checkAuthorization (data, done) {
  // a role the user must have is set in the config
  if (config.oauth2.accessRole) {
    // check if we know which claim contains the list of groups a user is in
    if (!config.oauth2.rolesClaim) {
      // log error, but accept all logins
      logger.error('oauth2: "accessRole" is configured, but "rolesClaim" is missing from the config. Can\'t check group membership!')
    } else {
      // parse and check role data
      const roles = extractProfileAttribute(data, config.oauth2.rolesClaim)
      if (!roles) {
        logger.error('oauth2: "accessRole" is configured, but user profile doesn\'t contain roles attribute. Permission denied')
        return done('Permission denied', null)
      }
      if (!roles.includes(config.oauth2.accessRole)) {
        const username = extractProfileAttribute(data, config.oauth2.userProfileUsernameAttr)
        logger.debug(`oauth2: user "${username}" doesn't have the required role. Permission denied`)
        return done('Permission denied', null)
      }
    }
  }
}

passport.use(new OAuth2CustomStrategy({
  authorizationURL: config.oauth2.authorizationURL,
  tokenURL: config.oauth2.tokenURL,
  clientID: config.oauth2.clientID,
  clientSecret: config.oauth2.clientSecret,
  callbackURL: config.serverURL + '/auth/oauth2/callback',
  workspaceURL: config.oauth2.workspaceURL,
  userProfileURL: config.oauth2.userProfileURL,
  scope: config.oauth2.scope,
  state: true
}, passportGeneralCallback))

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
