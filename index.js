const auth = require('basic-auth');
const Boom = require('@hapi/boom');
const autoBind = require('auto-bind');

class Policies {
  constructor(config = {}, findByTokenFn) {
    this.config = { ...config };
    if (typeof findByTokenFn !== 'function') {
      throw new TypeError('findByTokenFn must be defined and return a Promise');
    }

    this.findByTokenFn = findByTokenFn;
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
        ctx.flash(
          'warning',
          ctx.translate
            ? ctx.translate('LOGIN_REQUIRED')
            : 'Please log in to view the page you requested.'
        );
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
          ctx.translate
            ? ctx.translate('INVALID_API_CREDENTIALS')
            : 'Invalid API credentials.',
          this.config.appName
        )
      );

    const user = await this.findByTokenFn(credentials.name);

    if (!user)
      return ctx.throw(
        Boom.unauthorized(
          ctx.translate
            ? ctx.translate('INVALID_API_TOKEN')
            : 'Invalid API token.',
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
      return ctx.throw(
        Boom.unauthorized(
          ctx.translate
            ? ctx.translate('IS_NOT_ADMIN')
            : 'You do not belong to the administrative user group.'
        )
      );
    await next();
  }
}

module.exports = Policies;
