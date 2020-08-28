# fastify-guard
> A simple user role and scope checker plugin to protect endpoints for [Fastify](https://github.com/fastify/fastify).

[![NPM](https://nodei.co/npm/fastify-guard.png)](https://nodei.co/npm/fastify-guard/)

`fastify-guard` is designed to protect API endpoints by checking authenticated user roles and/or scopes if they met or not. It can be accessible as a decorator, named `guard`. `role` and `scope` are exposed guard methods and both generate hook functions for routes under the hood. 

`fastify-guard` is supposed to be used in `preHandler` hook.

## Options

| Name              | Type       | Default   | Description                                                                                                          |
| ---               | ---        | ---       | ---                                                                                                                  |
| requestProperty   | string     | `user`    | The authenticated user property name that fastify-guard will search in request object                                |
| roleProperty      | string     | `role`    | The role property name that fastify-guard will search in authenticated user object                                   |
| scopeProperty     | string     | `scope`   | The scope property name that fastify-guard will search in authenticated user object                                  |
| errorHandler      | function   | undefined | Custom error handler to manipulate the response that will be returned. As fallback, default HTTP error messages will be returned. |

## Examples

```js
// get required modules
const fastify = require('fastify')()
const fastifyGuard = require('fastify-guard')

// register fastify-guard plugin
fastify.register(
  fastifyGuard,
  {
    errorHandler: (result, req, reply) => {
      return reply.send('you are not allowed to call this route')
    }
  }
)

// this route can only be called by users who has 'admin' role
fastify.get(
  '/',
  { preHandler: [fastify.guard.role(['admin'])] },
  (req, reply) => {
    // 'user' should already be defined in req object
    reply.send(req.user)
  }
)

// initialize the fastify server
fastify.listen(3000, () => {
  console.log('Fastify server is running on port: 3000')
})

/*
http://localhost:3000 -> will print out below result if the authenticated user does not have 'admin' role

{
  "statusCode": 401,
  "error": "Unauthorized",
  "message": "you are not allowed to call this route"
}
*/
```

## Installation
`npm install fastify-guard`

## Contribution
Contributions and pull requests are kindly welcomed!

## License
This project is licensed under the terms of the [MIT license](https://github.com/hsynlms/fastify-guard/blob/master/LICENSE).
