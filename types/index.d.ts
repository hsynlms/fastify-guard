import createHttpError from 'http-errors'
import {
  FastifyPluginCallback,
  FastifyReply,
  FastifyRequest,
  preHandlerHookHandler
} from 'fastify'

interface FastifyGuard {
  hasRole(
    request: FastifyRequest,
    role: string
  ): boolean | createHttpError.HttpError
  hasScope(
    request: FastifyRequest,
    scope: string
  ): boolean | createHttpError.HttpError
  role(...roles: string[]): preHandlerHookHandler
  role(roles: string[]): preHandlerHookHandler
  scope(...scopes: string[]): preHandlerHookHandler
  scope(scopes: string[]): preHandlerHookHandler
}

declare module 'fastify' {
  interface FastifyInstance {
    guard: FastifyGuard
  }
}

declare const fastifyGuard: FastifyPluginCallback<{
  errorHandler?(
    result: createHttpError.HttpError,
    request: FastifyRequest,
    reply: FastifyReply
  ): any
  requestProperty?: string
  roleProperty?: string
  scopeProperty?: string
}>

export default fastifyGuard
