'use strict'

const fastifyPlugin = require('fastify-plugin')
const get = require('lodash.get')
const createError = require('http-errors')
const pkg = require('../package.json')

const defaults = {
  decorator: 'guard',
  requestProperty: 'user',
  roleProperty: 'role',
  scopeProperty: 'scope',
  errorHandler: undefined
}

const checkScopeAndRole = (arr, req, options, property) => {
  for (let i = 0; i < arr.length; i++) {
    const item = arr[i]

    if (typeof item !== 'string' && !Array.isArray(item)) {
      return createError(500, `roles/scopes parameter expected to be an array or string but got: ${typeof item}`)
    }
  }

  const user = get(req, options.requestProperty, undefined)
  if (typeof user === 'undefined') {
    return createError(500, `user object (${options.requestProperty}) was not found in request object`)
  }

  let permissions
  permissions = get(user, options[property], undefined)
  if (typeof permissions === 'undefined') {
    return createError(500, `${property} was not found in user object`)
  }
  if (typeof permissions === 'string' && property === 'scopeProperty') {
    permissions = permissions.split(' ')
  }

  if (!Array.isArray(permissions)) {
    return createError(500, `${property} expected to be an aray but got: ${typeof permissions}`)
  }

  let sufficient = false

  // loop roles/scopes array list (may contain sub arrays)
  arr.forEach(x => {
    sufficient =
      sufficient || (
        Array.isArray(x)
          ? x.every(
              scope => {
                return permissions.indexOf(scope) >= 0
              }
            )
          : permissions.indexOf(x) >= 0
      )
  })

  return sufficient
    ? null
    : createError(403, 'insufficient permission')
}

const hasScopeAndRole = (value, req, options, property) => {
  if (typeof req !== 'object') {
    throw new Error(`"request" is expected to be an object but got: ${typeof req}`)
  }

  if (typeof value !== 'string') {
    throw new Error(`"value" is expected to be a string but got: ${typeof value}`)
  }

  if (!value) {
    throw new Error('"value" cannot be empty.')
  }

  const user = get(req, options.requestProperty, undefined)

  if (!user) {
    throw new Error('"user" was not found in the request')
  }

  let permissions
  permissions = get(user, options[property], undefined)

  if (typeof permissions === 'undefined') {
    throw new Error(`"${property}" was not found in user object`)
  }

  if (typeof permissions === 'string' && property === 'scopeProperty') {
    permissions = permissions.split(' ')
  }

  if (!Array.isArray(permissions)) {
    throw new Error(`"${property}" expected to be an aray but got: ${typeof permissions}`)
  }

  return permissions.indexOf(value) >= 0
}

const Guard = function (options) {
  this._options = options
}

Guard.prototype = {
  hasRole: function (request, role) {
    return hasScopeAndRole(role, request, this._options, 'roleProperty')
  },
  role: function (...roles) {
    // thanks javascript :)
    const self = this

    // middleware to check authenticated user role(s)
    return (req, reply, done) => {
      const result = checkScopeAndRole(roles, req, self._options, 'roleProperty')

      // use custom handler if possible
      if (result && self._options.errorHandler) {
        return self._options.errorHandler(result, req, reply)
      }

      // use predefined handler as fallback
      return done(result)
    }
  },
  hasScope: function (request, scope) {
    return hasScopeAndRole(scope, request, this._options, 'scopeProperty')
  },
  scope: function (...scopes) {
    // thanks javascript :)
    const self = this

    // middleware to check authenticated user scope(s)
    return (req, reply, done) => {
      const result = checkScopeAndRole(scopes, req, self._options, 'scopeProperty')

      // use custom handler if possible
      if (result && self._options.errorHandler) {
        return self._options.errorHandler(result, req, reply)
      }

      // use predefined handler as fallback
      return done(result)
    }
  }
}

function guardPlugin (fastify, opts, next) {
  const options = Object.assign({}, defaults, opts)

  if (options.errorHandler && typeof options.errorHandler !== 'function') {
    throw new Error('custom error handler must be a function')
  }

  fastify.decorate(options.decorator, new Guard(options))

  next()
}

module.exports = fastifyPlugin(
  guardPlugin,
  {
    fastify: '4.x',
    name: pkg.name
  }
)
