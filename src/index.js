'use strict'

// get required modules
const fastifyPlugin = require('fastify-plugin')
const get = require('lodash.get')
const createError = require('http-errors')
const pkg = require('../package.json')

// plugin defaults
const defaults = {
  decorator: 'guard',
  requestProperty: 'user',
  roleProperty: 'role',
  scopeProperty: 'scope',
  errorHandler: undefined
}

// definition of role and scope checker function
const checkScopeAndRole = (arr, req, options, property) => {
  for (let i = 0; i < arr.length; i++) {
    const item = arr[i]

    if (typeof item !== 'string' && !Array.isArray(item)) {
      return createError(500, `roles/scopes parameter excpected to be an array or string but got: ${typeof item}`)
    }
  }

  const user = get(req, options.requestProperty, undefined)
  if (typeof user === 'undefined') {
    return createError(500, `user object (${options.requestProperty}) was not found in request object`)
  }

  const permissions = get(user, options[property], undefined)
  if (typeof permissions === 'undefined') {
    return createError(500, `${property} was not found in user object`)
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

// definition of guard function
const Guard = function (options) {
  this._options = options
}

Guard.prototype = {
  role: function (...roles) {
    // thanks javascript :)
    const self = this

    // middleware to check authenticated user role(s)
    return (req, reply, done) => {
      const result = checkScopeAndRole(roles, req, self._options, 'roleProperty')

      // use cutom handler if possible
      if (result && self._options.errorHandler) {
        return self._options.errorHandler(result, req, reply)
      }

      // use predefined handler as fallback
      return done(result)
    }
  },
  scope: function (...scopes) {
    // thanks javascript :)
    const self = this

    // middleware to check authenticated user scıoe(s)
    return (req, reply, done) => {
      const result = checkScopeAndRole(scopes, req, self._options, 'scopeProperty')

      // use cutom handler if possible
      if (result && self._options.errorHandler) {
        return self._options.errorHandler(result, req, reply)
      }

      // use predefined handler as fallback
      return done(result)
    }
  }
}

// declaration of guard plugin for fastify
function guardPlugin (fastify, opts, next) {
  // combine defaults with provided options
  const options = Object.assign({}, defaults, opts)

  // validation
  if (options.errorHandler && typeof options.errorHandler !== 'function') {
    throw new Error('custom error handler must be a function')
  }

  // register the guard as a decorator
  fastify.decorate(options.decorator, new Guard(options))

  // done
  next()
}

// export the plugin
module.exports = fastifyPlugin(
  guardPlugin,
  {
    fastify: '3.x',
    name: pkg.name
  }
)
