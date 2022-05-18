'use strict'

const Fastify = require('fastify')
const fastifyGuard = require('./src/index')

const generateServer =
  async pluginOpts => {
    const fastify = new Fastify()

    await fastify.register(fastifyGuard, pluginOpts)

    // simulation for user authentication process
    fastify.addHook('onRequest', (req, reply, done) => {
      req.user = {
        id: 306,
        name: 'Huseyin',
        role: ['user', 'admin', 'editor'],
        scope: ['profile', 'email', 'openid'],
        scp: 'profile email openid',
        location: 'Istanbul'
      }

      done()
    })

    return fastify
  }

// test cases

// eslint-disable-next-line
test('sufficient hasRole check', done => {
  generateServer()
    .then(fastify => {
      fastify.get('/', (req, reply) => {
        const isOk = fastify.guard.hasRole(req, 'user')
        reply.send(isOk)
      })

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.payload).toBe('true')
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('insufficient hasRole check', done => {
  generateServer()
    .then(fastify => {
      fastify.get('/', (req, reply) => {
        const isOk = fastify.guard.hasRole(req, 'cmo')
        reply.send(isOk)
      })

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.payload).toBe('false')
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('hasRole argument validations', done => {
  generateServer()
    .then(fastify => {
      fastify.get('/', (req, reply) => {
        const isOk =
          fastify.guard.hasRole(req, '') ||
          fastify.guard.hasRole(null, 'user') ||
          fastify.guard.hasRole()

        reply.send(isOk)
      })

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.statusCode).toBe(500)
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('sufficient hasScope check', done => {
  generateServer()
    .then(fastify => {
      fastify.get('/', (req, reply) => {
        const isOk = fastify.guard.hasScope(req, 'profile')
        reply.send(isOk)
      })

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.payload).toBe('true')
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('insufficient hasScope check', done => {
  generateServer()
    .then(fastify => {
      fastify.get('/', (req, reply) => {
        const isOk = fastify.guard.hasScope(req, 'base')
        reply.send(isOk)
      })

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.payload).toBe('false')
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('hasScope argument validations', done => {
  generateServer()
    .then(fastify => {
      fastify.get('/', (req, reply) => {
        const isOk =
          fastify.guard.hasScope(req, '') ||
          fastify.guard.hasScope(null, 'profile') ||
          fastify.guard.hasScope()

        reply.send(isOk)
      })

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.statusCode).toBe(500)
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('sufficient role permission (check OR case by providing two roles as arguments)', done => {
  generateServer()
    .then(fastify => {
      fastify.get(
        '/',
        { preHandler: [fastify.guard.role('admin', ['author'])] },
        (req, reply) => {
          reply.send()
        }
      )

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.payload).toBe('')
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('insufficient role permission (check OR case by providing two roles as arguments)', done => {
  generateServer()
    .then(fastify => {
      fastify.get(
        '/',
        { preHandler: [fastify.guard.role('author', ['ceo'])] },
        (req, reply) => {
          reply.send()
        }
      )

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.statusCode).toBe(403)
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('sufficient scope permission (check OR case by providing two scopes as arguments)', done => {
  generateServer()
    .then(fastify => {
      fastify.get(
        '/',
        { preHandler: [fastify.guard.scope('email', ['user:read'])] },
        (req, reply) => {
          reply.send()
        }
      )

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.payload).toBe('')
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('insufficient scope permission (check OR case by providing two scopes as arguments)', done => {
  generateServer()
    .then(fastify => {
      fastify.get(
        '/',
        { preHandler: [fastify.guard.scope('user:read', ['user:write'])] },
        (req, reply) => {
          reply.send()
        }
      )

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.statusCode).toBe(403)
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('sufficient role permission (only string as the argument)', done => {
  generateServer()
    .then(fastify => {
      fastify.get(
        '/',
        { preHandler: [fastify.guard.role('admin')] },
        (req, reply) => {
          reply.send()
        }
      )

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.payload).toBe('')
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('insufficient role permission (only string as the argument)', done => {
  generateServer()
    .then(fastify => {
      fastify.get(
        '/',
        { preHandler: [fastify.guard.role('author')] },
        (req, reply) => {
          reply.send()
        }
      )

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.statusCode).toBe(403)
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('sufficient scope permission (only string as the argument)', done => {
  generateServer()
    .then(fastify => {
      fastify.get(
        '/',
        { preHandler: [fastify.guard.scope('email')] },
        (req, reply) => {
          reply.send()
        }
      )

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.payload).toBe('')
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('insufficient scope permission (only string as the argument)', done => {
  generateServer()
    .then(fastify => {
      fastify.get(
        '/',
        { preHandler: [fastify.guard.scope('user:read')] },
        (req, reply) => {
          reply.send()
        }
      )

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.statusCode).toBe(403)
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('sufficient role permission', done => {
  generateServer()
    .then(fastify => {
      fastify.get(
        '/',
        { preHandler: [fastify.guard.role(['admin'])] },
        (req, reply) => {
          reply.send()
        }
      )

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.payload).toBe('')
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('insufficient role permission', done => {
  generateServer()
    .then(fastify => {
      fastify.get(
        '/',
        { preHandler: [fastify.guard.role(['author'])] },
        (req, reply) => {
          reply.send()
        }
      )

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.statusCode).toBe(403)
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('sufficient scope permission', done => {
  generateServer()
    .then(fastify => {
      fastify.get(
        '/',
        { preHandler: [fastify.guard.scope(['email'])] },
        (req, reply) => {
          reply.send()
        }
      )

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.payload).toBe('')
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('insufficient scope permission', done => {
  generateServer()
    .then(fastify => {
      fastify.get(
        '/',
        { preHandler: [fastify.guard.scope(['user:read'])] },
        (req, reply) => {
          reply.send()
        }
      )

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.statusCode).toBe(403)
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('sufficient role and scope permissions', done => {
  generateServer()
    .then(fastify => {
      fastify.get(
        '/',
        {
          preHandler: [
            fastify.guard.role(['admin']),
            fastify.guard.scope(['email'])
          ]
        },
        (req, reply) => {
          reply.send()
        }
      )

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.payload).toBe('')
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('insufficient role and scope permissions', done => {
  generateServer()
    .then(fastify => {
      fastify.get(
        '/',
        {
          preHandler: [
            fastify.guard.role(['author']),
            fastify.guard.scope(['user:read'])
          ]
        },
        (req, reply) => {
          reply.send()
        }
      )

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.statusCode).toBe(403)
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('sufficient role and insufficient scope permissions', done => {
  generateServer()
    .then(fastify => {
      fastify.get(
        '/',
        {
          preHandler: [
            fastify.guard.role(['admin']),
            fastify.guard.scope(['user:read'])
          ]
        },
        (req, reply) => {
          reply.send()
        }
      )

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.statusCode).toBe(403)
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('insufficient role and sufficient scope permissions', done => {
  generateServer()
    .then(fastify => {
      fastify.get(
        '/',
        {
          preHandler: [
            fastify.guard.role(['author']),
            fastify.guard.scope(['email'])
          ]
        },
        (req, reply) => {
          reply.send()
        }
      )

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.statusCode).toBe(403)
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('wrong argument error', done => {
  generateServer()
    .then(fastify => {
      fastify.get(
        '/',
        { preHandler: [fastify.guard.role(true)] },
        (req, reply) => {
          reply.send()
        }
      )

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.statusCode).toBe(500)
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('custom error handler (sufficient case)', done => {
  generateServer({
    errorHandler: (result, req, reply) => {
      return reply.send('custom error handler works!')
    }
  })
    .then(fastify => {
      fastify.get(
        '/',
        { preHandler: [fastify.guard.role(['admin'])] },
        (req, reply) => {
          reply.send()
        }
      )

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.payload).toBe('')
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('custom error handler (insufficient case)', done => {
  generateServer({
    errorHandler: (result, req, reply) => {
      return reply.send('custom error handler works!')
    }
  })
    .then(fastify => {
      fastify.get(
        '/',
        { preHandler: [fastify.guard.scope(['user:read'])] },
        (req, reply) => {
          reply.send()
        }
      )

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.payload).toBe('custom error handler works!')
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('OIDC style hasScope check', done => {
  generateServer({
    scopeProperty: 'scp'
  })
    .then(fastify => {
      fastify.get('/', (req, reply) => {
        const isOk = fastify.guard.hasScope(req, 'profile')
        reply.send(isOk)
      })

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.payload).toBe('true')
          done()

          fastify.close()
        }
      )
    })
})

// eslint-disable-next-line
test('OIDC style scope permission (check OR case by providing two scopes as arguments)', done => {
  generateServer({
    scopeProperty: 'scp'
  })
    .then(fastify => {
      fastify.get(
        '/',
        { preHandler: [fastify.guard.scope('email', ['user:read'])] },
        (req, reply) => {
          reply.send()
        }
      )

      fastify.inject(
        { method: 'GET', url: '/' },
        // eslint-disable-next-line
        (err, res) => {
          // eslint-disable-next-line
          expect(res.payload).toBe('')
          done()

          fastify.close()
        }
      )
    })
})
