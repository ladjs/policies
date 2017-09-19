const auth = require('basic-auth');
const Boom = require('boom');
const autoBind = require('auto-bind');

class Policies {
  constructor(config = {}, findByTokenFn) {
    this.config = Object.assign({}, config);
    if (typeof findByTokenFn !== 'function') {
      throw new TypeError('findByTokenFn must be defined an return a Promise');
    }
    this.findByToken = findByTokenFn;
    autoBind(this);
  }

  ensureLoggedIn(ctx, next) {
    // a more simpler version that is adapted from
    // `koa-ensure-login` to use async/await
    // (this is adapted = require(the original `connect-ensure-login`)
    // <https://github.com/RobinQu/koa-ensure-login>
    // <https://github.com/jaredhanson/connect-ensure-login>

    if (!ctx.isAuthenticated()) {
      ctx.session.returnTo = ctx.originalUrl || ctx.req.url;
      if (!ctx.is('json'))
        ctx.flash('warning', ctx.translate('LOGIN_REQUIRED'));
      ctx.redirect('/login');
      return;
    }

    return next();
  }

  async ensureApiToken(ctx, next) {
    const credentials = auth(ctx.req);

    if (
      typeof credentials === 'undefined' ||
      typeof credentials.name !== 'string' ||
      !credentials.name
    )
      return ctx.throw(
        Boom.unauthorized(
          ctx.translate('INVALID_API_CREDENTIALS'),
          this.config.appName
        )
      );

    const user = await this.findByToken(credentials.name);

    if (!user)
      return ctx.throw(
        Boom.unauthorized(
          ctx.translate('INVALID_API_TOKEN'),
          this.config.appName
        )
      );

    await ctx.login(user, { session: false });

    return next();
  }

  async ensureLoggedOut(ctx, next) {
    if (ctx.isAuthenticated()) return ctx.redirect('/');
    await next();
  }

  async ensureAdmin(ctx, next) {
    if (!ctx.isAuthenticated() || ctx.state.user.group !== 'admin')
      return ctx.throw(Boom.unauthorized(ctx.translate('IS_NOT_ADMIN')));
    await next();
  }
}

module.exports = Policies;
