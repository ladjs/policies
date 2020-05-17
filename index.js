const auth = require('basic-auth');
const Boom = require('@hapi/boom');

function hasFlashAndAcceptsHTML(ctx) {
  return typeof ctx.flash === 'function' && ctx.accepts('html');
}

class Policies {
  constructor(config, findByTokenFn) {
    this.config = {
      verifyRoute: '/verify',
      loginRoute: '/login',
      loginOtpRoute: '/otp/login',
      schemeName: null,
      passport: {
        otpEnabled: 'otp_enabled'
      },
      userFields: {
        hasVerifiedEmail: 'has_verified_email'
      },
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
    this.ensureOtp = this.ensureOtp.bind(this);
  }

  async checkVerifiedEmail(ctx, next) {
    if (!ctx.isAuthenticated()) {
      ctx.session.returnTo = ctx.originalUrl || ctx.req.url;
      const message = ctx.translate
        ? ctx.translate('LOGIN_REQUIRED')
        : 'Please log in to view the page you requested.';

      if (ctx.api) return ctx.throw(Boom.unauthorized(message));

      if (hasFlashAndAcceptsHTML(ctx)) ctx.flash('warning', message);

      ctx.redirect(
        typeof ctx.state.l === 'function'
          ? ctx.state.l(this.config.loginRoute)
          : this.config.loginRoute
      );
      return;
    }

    if (!this.config.userFields.hasVerifiedEmail) return next();

    if (ctx.state.user[this.config.userFields.hasVerifiedEmail]) return next();

    if (
      typeof ctx.pathWithoutLocale === 'string'
        ? ctx.pathWithoutLocale === this.config.verifyRoute
        : ctx.path === this.config.verifyRoute
    )
      return next();

    const message = ctx.translate
      ? ctx.translate('EMAIL_VERIFICATION_REQUIRED')
      : 'Please verify your email address to continue.';

    if (ctx.api) return ctx.throw(Boom.unauthorized(message));

    if (hasFlashAndAcceptsHTML(ctx)) ctx.flash('warning', message);

    const redirect = `${
      this.config.verifyRoute
    }?redirect_to=${ctx.originalUrl || ctx.req.url}`;
    ctx.redirect(
      typeof ctx.state.l === 'function' ? ctx.state.l(redirect) : redirect
    );
  }

  async ensureOtp(ctx, next) {
    if (!process.env.AUTH_OTP_ENABLED) return next();

    if (
      !ctx.isAuthenticated() ||
      (ctx.state.user[this.config.passport.fields.otpEnabled] &&
        !ctx.session.otp)
    ) {
      ctx.session.returnTo = ctx.originalUrl || ctx.req.url;
      const message = ctx.translate
        ? ctx.translate('TWO_FACTOR_REQUIRED')
        : 'Please log in with two-factor authentication to view the page you requested.';
      if (hasFlashAndAcceptsHTML(ctx)) ctx.flash('warning', message);
      ctx.redirect(
        typeof ctx.state.l === 'function'
          ? ctx.state.l(this.config.loginOtpRoute)
          : this.config.loginOtpRoute
      );
      return;
    }

    return next();
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

      if (ctx.api) return ctx.throw(Boom.unauthorized(message));

      if (hasFlashAndAcceptsHTML(ctx)) ctx.flash('warning', message);

      ctx.redirect(
        typeof ctx.state.l === 'function'
          ? ctx.state.l(this.config.loginRoute)
          : this.config.loginRoute
      );
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
    if (ctx.isAuthenticated()) {
      ctx.session.returnTo = ctx.originalUrl || ctx.req.url;
      const message = ctx.translate
        ? ctx.translate('LOGOUT_REQUIRED')
        : 'Please log out to view the page you requested.';

      if (ctx.api) return ctx.throw(Boom.unauthorized(message));

      if (hasFlashAndAcceptsHTML(ctx)) ctx.flash('warning', message);

      ctx.redirect('back');
      return;
    }

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
