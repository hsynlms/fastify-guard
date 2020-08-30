'use strict'

// get required node modules
const fastify = require('fastify')()
const fastifyGuard = require('./src/index')
const chalk = require('chalk')

// defaults
const defaults = { port: 3000 }

;(async () => {
  // register the plugin
  await fastify.register(fastifyGuard)

  // simulation for user authentication process
  fastify.addHook('onRequest', (req, reply, done) => {
    req.user = {
      id: 306,
      name: 'Huseyin',
      role: ['user', 'admin', 'editor'],
      scope: ['profile', 'email', 'openid'],
      location: 'Istanbul'
    }

    // all done
    done()
  })

  // below routes are protected by fastify-guard
  fastify.get(
    '/',
    { preHandler: [fastify.guard.role('admin')] },
    (req, reply) => {
      // set return type
      reply.type('application/json')

      // return the user
      reply.send(req.user)
    }
  )

  fastify.get(
    '/insufficient',
    { preHandler: [fastify.guard.role(['supervisor'])] },
    (req, reply) => {
      // set return type
      reply.type('application/json')

      // return the user
      reply.send(req.user)
    }
  )

  // initialize the fastify server
  fastify.listen(defaults.port, () => {
    console.log(
      chalk.bgYellow(
        chalk.black(`Fastify server is running on port: ${defaults.port}`)
      )
    )
  })
})()
