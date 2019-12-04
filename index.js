const auth = require('basic-auth');
const Boom = require('@hapi/boom');

class Policies {
  constructor(config, findByTokenFn) {
    this.config = {
      hasVerifiedEmail: 'has_verified_email',
      verifyRoute: '/verify',
      loginRoute: '/login',
      schemeName: null,
      ...config
    };

    if (typeof findByTokenFn !== 'function')
      throw new TypeError('findByTokenFn must be defined and return a Promise');

    // bind the function to this instance
    this.findByTokenFn = findByTokenFn;

    // bind this
    this.checkVerifiedEmail = this.checkVerifiedEmail.bind(this);
    this.ensureLoggedIn = this.ensureLoggedIn.bind(this);
    this.ensureApiToken = this.ensureApiToken.bind(this);
    this.ensureLoggedOut = this.ensureLoggedOut.bind(this);
    this.ensureAdmin = this.ensureAdmin.bind(this);
  }

  async checkVerifiedEmail(ctx, next) {
    if (!ctx.isAuthenticated())
      return ctx.throw(
        Boom.unauthorized(
          ctx.translate
            ? ctx.translate('LOGIN_REQUIRED')
            : 'Please log in to view the page you requested.'
        )
      );

    if (!this.config.hasVerifiedEmail) return next();

    if (ctx.state.user[this.config.hasVerifiedEmail]) return next();

    ctx.session.returnTo = ctx.originalUrl || ctx.req.url;
    const message = ctx.translate
      ? ctx.translate('EMAIL_VERIFICATION_REQUIRED')
      : 'Please verify your email address to continue.';
    if (ctx.is('json')) {
      ctx.throw(Boom.unauthorized(message));
    } else {
      if (ctx.flash) ctx.flash('warning', message);
      ctx.redirect(this.config.verifyRoute);
    }
  }

  async ensureLoggedIn(ctx, next) {
    // a more simpler version that is adapted from
    // `koa-ensure-login` to use async/await
    // (this is adapted = require(the original `connect-ensure-login`)
    // <https://github.com/RobinQu/koa-ensure-login>
    // <https://github.com/jaredhanson/connect-ensure-login>

    if (!ctx.isAuthenticated()) {
      ctx.session.returnTo = ctx.originalUrl || ctx.req.url;
      const message = ctx.translate
        ? ctx.translate('LOGIN_REQUIRED')
        : 'Please log in to view the page you requested.';
      if (ctx.is('json')) {
        ctx.throw(Boom.unauthorized(message));
      } else {
        if (ctx.flash) ctx.flash('warning', message);
        ctx.redirect(this.config.loginRoute);
      }

      return;
    }

    // check if the user has a verified email
    return this.checkVerifiedEmail(ctx, next);
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
          this.config.schemeName
        )
      );

    const user = await this.findByTokenFn(credentials.name);

    if (!user)
      return ctx.throw(
        Boom.unauthorized(
          ctx.translate
            ? ctx.translate('INVALID_API_TOKEN')
            : 'Invalid API token.',
          this.config.schemeName
        )
      );

    await ctx.login(user, { session: false });

    // check if the user has a verified email
    return this.checkVerifiedEmail(ctx, next);
  }

  async ensureLoggedOut(ctx, next) {
    if (ctx.isAuthenticated()) return ctx.redirect('/');
    return next();
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
    // check if the user has a verified email
    return this.checkVerifiedEmail(ctx, next);
  }
}

module.exports = Policies;
