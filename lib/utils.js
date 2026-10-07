'use strict'

exports.isSQLite = function isSQLite (sequelize) {
  return sequelize.options.dialect === 'sqlite'
}

exports.isMySQL = function isMySQL (sequelize) {
  return ['mysql', 'mariadb'].includes(sequelize.options.dialect)
}

exports.getImageMimeType = function getImageMimeType (imagePath) {
  const fileExtension = /[^.]+$/.exec(imagePath)

  switch (fileExtension[0].toLowerCase()) {
    case 'bmp':
      return 'image/bmp'
    case 'gif':
      return 'image/gif'
    case 'jpg':
    case 'jpeg':
      return 'image/jpeg'
    case 'png':
      return 'image/png'
    case 'tiff':
      return 'image/tiff'
    case 'svg':
      return 'image/svg+xml'
    default:
      return undefined
  }
}

// `paths` holds exact paths and regular expressions
exports.useUnless = function excludeRoute (paths, middleware) {
  return function (req, res, next) {
    if (paths.some(p => p instanceof RegExp ? p.test(req.path) : p === req.path)) {
      return next()
    }
    return middleware(req, res, next)
  }
}

// true when aquila-website reported the user as a superuser at the last check
exports.isSuperuser = function isSuperuser (user) {
  return !!(user && user.superuser === true)
}

// Forgejo login stored in the user's OAuth2 profile, or null
exports.loginOf = function loginOf (user) {
  try {
    return JSON.parse(user.profile).username || null
  } catch (err) {
    return null
  }
}
