import { expectType } from 'tsd'
import createHttpError from 'http-errors'

import Fastify, {
  FastifyReply,
  FastifyRequest,
  preHandlerHookHandler
} from 'fastify'
import fastifyGuard from '.'

const fastify = Fastify()

fastify.register(fastifyGuard, {
  errorHandler: (result, req, reply) => {
    return reply.send('string')
  },
  requestProperty: 'string',
  roleProperty: 'string',
  scopeProperty: 'string'
})

;(request: FastifyRequest, reply: FastifyReply) => {
  expectType<boolean | createHttpError.HttpError>(
    fastify.guard.hasRole(request, 'user')
  )

  expectType<boolean | createHttpError.HttpError>(
    fastify.guard.hasScope(request, 'read')
  )
}
expectType<preHandlerHookHandler>(fastify.guard.role('ceo'))
expectType<preHandlerHookHandler>(fastify.guard.role('ceo', 'cto'))
expectType<preHandlerHookHandler>(fastify.guard.role(['string']))
expectType<preHandlerHookHandler>(fastify.guard.scope('profile'))
expectType<preHandlerHookHandler>(fastify.guard.scope('profile', 'blog'))
expectType<preHandlerHookHandler>(fastify.guard.scope(['string']))
