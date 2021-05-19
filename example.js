'use strict'

const fastify = require('fastify')()
const fastifyGuard = require('./src/index')
const chalk = require('chalk')

const defaults = { port: 3000 }

;(async () => {
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

    done()
  })

  fastify.get(
    '/',
    { preHandler: [fastify.guard.role('admin')] },
    (req, reply) => {
      reply
        .type('application/json')
        .send(req.user)
    }
  )

  fastify.get(
    '/insufficient',
    { preHandler: [fastify.guard.role(['supervisor'])] },
    (req, reply) => {
      reply
        .type('application/json')
        .send(req.user)
    }
  )

  fastify.listen(defaults.port, () => {
    console.log(
      chalk.bgYellow(
        chalk.black(`Fastify server is running on port: ${defaults.port}`)
      )
    )
  })
})()
