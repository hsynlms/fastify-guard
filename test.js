'use strict'

// get required node modules
const Fastify = require('fastify')
const fastifyGuard = require('./src/index')

// fastify server generator
const generateServer = async (pluginOpts) => {
  // initialize fastify server
  const fastify = new Fastify()

  // register the plugin
  await fastify.register(fastifyGuard, pluginOpts)

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

  // return the instance
  return fastify
}

// test cases

// eslint-disable-next-line
test('sufficient role permission (check OR case by providing two roles as arguments)', async done => {
  // initialize a fastify server
  const fastify = await generateServer()

  // define a route
  fastify.get('/', { preHandler: [fastify.guard.role('admin', ['author'])] }, (req, reply) => {
    // send response
    reply.send()
  })

  // test
  fastify.inject(
    { method: 'GET', url: '/' },
    // eslint-disable-next-line
    (err, res) => {
      // eslint-disable-next-line
      expect(res.payload).toBe('')
      done()

      // close fastify server
      fastify.close()
    }
  )
})

// eslint-disable-next-line
test('insufficient role permission (check OR case by providing two roles as arguments)', async done => {
  // initialize a fastify server
  const fastify = await generateServer()

  // define a route
  fastify.get('/', { preHandler: [fastify.guard.role('author', ['ceo'])] }, (req, reply) => {
    // send response
    reply.send()
  })

  // test
  fastify.inject(
    { method: 'GET', url: '/' },
    // eslint-disable-next-line
    (err, res) => {
      // eslint-disable-next-line
      expect(res.statusCode).toBe(403)
      done()

      // close fastify server
      fastify.close()
    }
  )
})

// eslint-disable-next-line
test('sufficient scope permission (check OR case by providing two scopes as arguments)', async done => {
  // initialize a fastify server
  const fastify = await generateServer()

  // define a route
  fastify.get('/', { preHandler: [fastify.guard.scope('email', ['user:read'])] }, (req, reply) => {
    // send response
    reply.send()
  })

  // test
  fastify.inject(
    { method: 'GET', url: '/' },
    // eslint-disable-next-line
    (err, res) => {
      // eslint-disable-next-line
      expect(res.payload).toBe('')
      done()

      // close fastify server
      fastify.close()
    }
  )
})

// eslint-disable-next-line
test('insufficient scope permission (check OR case by providing two scopes as arguments)', async done => {
  // initialize a fastify server
  const fastify = await generateServer()

  // define a route
  fastify.get('/', { preHandler: [fastify.guard.scope('user:read', ['user:write'])] }, (req, reply) => {
    // send response
    reply.send()
  })

  // test
  fastify.inject(
    { method: 'GET', url: '/' },
    // eslint-disable-next-line
    (err, res) => {
      // eslint-disable-next-line
      expect(res.statusCode).toBe(403)
      done()

      // close fastify server
      fastify.close()
    }
  )
})

// eslint-disable-next-line
test('sufficient role permission (only string as the argument)', async done => {
  // initialize a fastify server
  const fastify = await generateServer()

  // define a route
  fastify.get('/', { preHandler: [fastify.guard.role('admin')] }, (req, reply) => {
    // send response
    reply.send()
  })

  // test
  fastify.inject(
    { method: 'GET', url: '/' },
    // eslint-disable-next-line
    (err, res) => {
      // eslint-disable-next-line
      expect(res.payload).toBe('')
      done()

      // close fastify server
      fastify.close()
    }
  )
})

// eslint-disable-next-line
test('insufficient role permission (only string as the argument)', async done => {
  // initialize a fastify server
  const fastify = await generateServer()

  // define a route
  fastify.get('/', { preHandler: [fastify.guard.role('author')] }, (req, reply) => {
    // send response
    reply.send()
  })

  // test
  fastify.inject(
    { method: 'GET', url: '/' },
    // eslint-disable-next-line
    (err, res) => {
      // eslint-disable-next-line
      expect(res.statusCode).toBe(403)
      done()

      // close fastify server
      fastify.close()
    }
  )
})

// eslint-disable-next-line
test('sufficient scope permission (only string as the argument)', async done => {
  // initialize a fastify server
  const fastify = await generateServer()

  // define a route
  fastify.get('/', { preHandler: [fastify.guard.scope('email')] }, (req, reply) => {
    // send response
    reply.send()
  })

  // test
  fastify.inject(
    { method: 'GET', url: '/' },
    // eslint-disable-next-line
    (err, res) => {
      // eslint-disable-next-line
      expect(res.payload).toBe('')
      done()

      // close fastify server
      fastify.close()
    }
  )
})

// eslint-disable-next-line
test('insufficient scope permission (only string as the argument)', async done => {
  // initialize a fastify server
  const fastify = await generateServer()

  // define a route
  fastify.get('/', { preHandler: [fastify.guard.scope('user:read')] }, (req, reply) => {
    // send response
    reply.send()
  })

  // test
  fastify.inject(
    { method: 'GET', url: '/' },
    // eslint-disable-next-line
    (err, res) => {
      // eslint-disable-next-line
      expect(res.statusCode).toBe(403)
      done()

      // close fastify server
      fastify.close()
    }
  )
})

// eslint-disable-next-line
test('sufficient role permission', async done => {
  // initialize a fastify server
  const fastify = await generateServer()

  // define a route
  fastify.get('/', { preHandler: [fastify.guard.role(['admin'])] }, (req, reply) => {
    // send response
    reply.send()
  })

  // test
  fastify.inject(
    { method: 'GET', url: '/' },
    // eslint-disable-next-line
    (err, res) => {
      // eslint-disable-next-line
      expect(res.payload).toBe('')
      done()

      // close fastify server
      fastify.close()
    }
  )
})

// eslint-disable-next-line
test('insufficient role permission', async done => {
  // initialize a fastify server
  const fastify = await generateServer()

  // define a route
  fastify.get('/', { preHandler: [fastify.guard.role(['author'])] }, (req, reply) => {
    // send response
    reply.send()
  })

  // test
  fastify.inject(
    { method: 'GET', url: '/' },
    // eslint-disable-next-line
    (err, res) => {
      // eslint-disable-next-line
      expect(res.statusCode).toBe(403)
      done()

      // close fastify server
      fastify.close()
    }
  )
})

// eslint-disable-next-line
test('sufficient scope permission', async done => {
  // initialize a fastify server
  const fastify = await generateServer()

  // define a route
  fastify.get('/', { preHandler: [fastify.guard.scope(['email'])] }, (req, reply) => {
    // send response
    reply.send()
  })

  // test
  fastify.inject(
    { method: 'GET', url: '/' },
    // eslint-disable-next-line
    (err, res) => {
      // eslint-disable-next-line
      expect(res.payload).toBe('')
      done()

      // close fastify server
      fastify.close()
    }
  )
})

// eslint-disable-next-line
test('insufficient scope permission', async done => {
  // initialize a fastify server
  const fastify = await generateServer()

  // define a route
  fastify.get('/', { preHandler: [fastify.guard.scope(['user:read'])] }, (req, reply) => {
    // send response
    reply.send()
  })

  // test
  fastify.inject(
    { method: 'GET', url: '/' },
    // eslint-disable-next-line
    (err, res) => {
      // eslint-disable-next-line
      expect(res.statusCode).toBe(403)
      done()

      // close fastify server
      fastify.close()
    }
  )
})

// eslint-disable-next-line
test('sufficient role and scope permissions', async done => {
  // initialize a fastify server
  const fastify = await generateServer()

  // define a route
  fastify.get(
    '/',
    {
      preHandler: [
        fastify.guard.role(['admin']),
        fastify.guard.scope(['email'])
      ]
    },
    (req, reply) => {
      // send response
      reply.send()
    }
  )

  // test
  fastify.inject(
    { method: 'GET', url: '/' },
    // eslint-disable-next-line
    (err, res) => {
      // eslint-disable-next-line
      expect(res.payload).toBe('')
      done()

      // close fastify server
      fastify.close()
    }
  )
})

// eslint-disable-next-line
test('insufficient role and scope permissions', async done => {
  // initialize a fastify server
  const fastify = await generateServer()

  // define a route
  fastify.get(
    '/',
    {
      preHandler: [
        fastify.guard.role(['author']),
        fastify.guard.scope(['user:read'])
      ]
    },
    (req, reply) => {
      // send response
      reply.send()
    }
  )

  // test
  fastify.inject(
    { method: 'GET', url: '/' },
    // eslint-disable-next-line
    (err, res) => {
      // eslint-disable-next-line
      expect(res.statusCode).toBe(403)
      done()

      // close fastify server
      fastify.close()
    }
  )
})

// eslint-disable-next-line
test('sufficient role and insufficient scope permissions', async done => {
  // initialize a fastify server
  const fastify = await generateServer()

  // define a route
  fastify.get(
    '/',
    {
      preHandler: [
        fastify.guard.role(['admin']),
        fastify.guard.scope(['user:read'])
      ]
    },
    (req, reply) => {
      // send response
      reply.send()
    }
  )

  // test
  fastify.inject(
    { method: 'GET', url: '/' },
    // eslint-disable-next-line
    (err, res) => {
      // eslint-disable-next-line
      expect(res.statusCode).toBe(403)
      done()

      // close fastify server
      fastify.close()
    }
  )
})

// eslint-disable-next-line
test('insufficient role and sufficient scope permissions', async done => {
  // initialize a fastify server
  const fastify = await generateServer()

  // define a route
  fastify.get(
    '/',
    {
      preHandler: [
        fastify.guard.role(['author']),
        fastify.guard.scope(['email'])
      ]
    },
    (req, reply) => {
      // send response
      reply.send()
    }
  )

  // test
  fastify.inject(
    { method: 'GET', url: '/' },
    // eslint-disable-next-line
    (err, res) => {
      // eslint-disable-next-line
      expect(res.statusCode).toBe(403)
      done()

      // close fastify server
      fastify.close()
    }
  )
})

// eslint-disable-next-line
test('wrong argument error', async done => {
  // initialize a fastify server
  const fastify = await generateServer()

  // define a route
  fastify.get('/', { preHandler: [fastify.guard.role(true)] }, (req, reply) => {
    // send response
    reply.send()
  })

  // test
  fastify.inject(
    { method: 'GET', url: '/' },
    // eslint-disable-next-line
    (err, res) => {
      // eslint-disable-next-line
      expect(res.statusCode).toBe(500)
      done()

      // close fastify server
      fastify.close()
    }
  )
})

// eslint-disable-next-line
test('custom error handler (sufficient case)', async done => {
  // initialize a fastify server
  const fastify = await generateServer({
    errorHandler: (result, req, reply) => {
      return reply.send('custom error handler works!')
    }
  })

  // define a route
  fastify.get('/', { preHandler: [fastify.guard.role(['admin'])] }, (req, reply) => {
    // send response
    reply.send()
  })

  // test
  fastify.inject(
    { method: 'GET', url: '/' },
    // eslint-disable-next-line
    (err, res) => {
      // eslint-disable-next-line
      expect(res.payload).toBe('')
      done()

      // close fastify server
      fastify.close()
    }
  )
})

// eslint-disable-next-line
test('custom error handler (insufficient case)', async done => {
  // initialize a fastify server
  const fastify = await generateServer({
    errorHandler: (result, req, reply) => {
      return reply.send('custom error handler works!')
    }
  })

  // define a route
  fastify.get('/', { preHandler: [fastify.guard.scope(['user:read'])] }, (req, reply) => {
    // send response
    reply.send()
  })

  // test
  fastify.inject(
    { method: 'GET', url: '/' },
    // eslint-disable-next-line
    (err, res) => {
      // eslint-disable-next-line
      expect(res.payload).toBe('custom error handler works!')
      done()

      // close fastify server
      fastify.close()
    }
  )
})
