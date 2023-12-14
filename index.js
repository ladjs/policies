const process = require('node:process');
const Boom = require('@hapi/boom');
const auth = require('basic-auth');
const isSANB = require('is-string-and-not-blank');
const { boolean } = require('boolean');
const { request } = require('undici');

function hasFlashAndAcceptsHTML(ctx) {
  return typeof ctx.flash === 'function' && ctx.accepts('html');
}

function hasTranslationHelper(ctx) {
  return typeof ctx.request === 'object' && typeof ctx.request.t === 'function';
}

class Policies {
  constructor(config, findByTokenFn) {
    this.config = {
      requireVerificationPostLogin: false,
      verifyRoute: '/verify',
      loginRoute: '/login',
      loginOtpRoute: '/otp/login',
      schemeName: null,
      passport: {
        fields: {
          otpEnabled: 'otp_enabled'
        }
      },
      userFields: {
        hasVerifiedEmail: 'has_verified_email'
      },
      turnstileEnabled: false,
      turnstileSecretKey: null,
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
    this.ensureTurnstile = this.ensureTurnstile.bind(this);
  }

  async checkVerifiedEmail(ctx, next) {
    if (!ctx.isAuthenticated()) {
      ctx.session.returnTo = ctx.originalUrl || ctx.req.url;
      const message = ctx.translate
        ? ctx.translate('LOGIN_REQUIRED')
        : 'Please log in to view the page you requested.';

      if (ctx.api) return ctx.throw(Boom.unauthorized(message));

      if (hasFlashAndAcceptsHTML(ctx)) {
        if (hasTranslationHelper(ctx)) {
          ctx.flash('custom', {
            title: ctx.request.t('Warning'),
            text: message,
            type: 'warning',
            toast: true,
            showConfirmButton: false,
            timer: 3000,
            position: 'top'
          });
        } else {
          ctx.flash('warning', message);
        }
      }

      const redirectTo =
        typeof ctx.state.l === 'function'
          ? ctx.state.l(this.config.loginRoute)
          : this.config.loginRoute;

      if (ctx.accepts('html')) ctx.redirect(redirectTo);
      else ctx.body = { message, redirectTo };

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

    if (hasFlashAndAcceptsHTML(ctx)) {
      if (hasTranslationHelper(ctx)) {
        ctx.flash('custom', {
          title: ctx.request.t('Warning'),
          text: message,
          type: 'warning',
          toast: true,
          showConfirmButton: false,
          timer: 3000,
          position: 'top'
        });
      } else {
        ctx.flash('warning', message);
      }
    }

    const redirect = `${this.config.verifyRoute}?redirect_to=${
      ctx.originalUrl || ctx.req.url
    }`;

    const redirectTo =
      typeof ctx.state.l === 'function' ? ctx.state.l(redirect) : redirect;

    if (ctx.accepts('html')) ctx.redirect(redirectTo);
    else ctx.body = { message, redirectTo };
  }

  async ensureOtp(ctx, next) {
    if (!boolean(process.env.AUTH_OTP_ENABLED)) return next();

    if (
      !ctx.isAuthenticated() ||
      (ctx.state.user[this.config.passport.fields.otpEnabled] &&
        !ctx.session.otp)
    ) {
      ctx.session.returnTo = ctx.originalUrl || ctx.req.url;
      const message = ctx.translate
        ? ctx.translate('TWO_FACTOR_REQUIRED')
        : 'Please log in with two-factor authentication to continue.';

      // if (hasFlashAndAcceptsHTML(ctx)) ctx.flash('warning', message);

      const redirectTo =
        typeof ctx.state.l === 'function'
          ? ctx.state.l(this.config.loginOtpRoute)
          : this.config.loginOtpRoute;

      if (ctx.accepts('html')) ctx.redirect(redirectTo);
      else ctx.body = { message, redirectTo };

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

      if (hasFlashAndAcceptsHTML(ctx)) {
        if (hasTranslationHelper(ctx)) {
          ctx.flash('custom', {
            title: ctx.request.t('Warning'),
            text: message,
            type: 'warning',
            toast: true,
            showConfirmButton: false,
            timer: 3000,
            position: 'top'
          });
        } else {
          ctx.flash('warning', message);
        }
      }

      const redirectTo =
        typeof ctx.state.l === 'function'
          ? ctx.state.l(this.config.loginRoute)
          : this.config.loginRoute;

      if (ctx.accepts('html')) ctx.redirect(redirectTo);
      else ctx.body = { message, redirectTo };

      return;
    }

    // check if the user has a verified email
    if (this.config.requireVerificationPostLogin)
      return this.checkVerifiedEmail(ctx, next);

    return next();
  }

  async ensureApiToken(ctx, next) {
    const credentials = auth(ctx.req);

    if (
      credentials === undefined ||
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

    const user = await this.findByTokenFn(credentials.name, ctx);

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

      if (hasFlashAndAcceptsHTML(ctx)) {
        if (hasTranslationHelper(ctx)) {
          ctx.flash('custom', {
            title: ctx.request.t('Warning'),
            text: message,
            type: 'warning',
            toast: true,
            showConfirmButton: false,
            timer: 3000,
            position: 'top'
          });
        } else {
          ctx.flash('warning', message);
        }
      }

      const redirectTo =
        ctx.get('Referrer') || typeof ctx.state.l === 'function'
          ? ctx.state.l('/')
          : '/';

      if (ctx.accepts('html')) ctx.redirect(redirectTo);
      else ctx.body = { message, redirectTo };

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

  async ensureTurnstile(ctx, next) {
    if (!boolean(this.config.turnstileEnabled)) return next();

    if (
      ctx.isAuthenticated() &&
      ctx.state.user &&
      ctx.state.user.group === 'admin'
    )
      return next();

    if (!isSANB(ctx.request.body['cf-turnstile-response'])) {
      const err = Boom.badRequest(
        ctx.translate
          ? ctx.translate('TURNSTILE_NOT_VERIFIED')
          : 'Turnstile not verified.'
      );
      err.is_turnstile = true;
      ctx.throw(err);
      return;
    }

    try {
      // <https://github.com/cloudflare/turnstile-demo-workers/blob/main/src/index.mjs>
      const res = await request(
        'https://challenges.cloudflare.com/turnstile/v0/siteverify',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            secret: this.config.turnstileSecretKey,
            response: ctx.request.body['cf-turnstile-response'],
            remoteip: ctx.request.headers['CF-Connecting-IP'] || ctx.ip
          })
        }
      );

      const body = await res.body.json();

      ctx.logger.debug('turnstile response', {
        headers: res.headers,
        statusCode: res.statusCode,
        body
      });

      if (body.success !== true) {
        // https://developers.cloudflare.com/turnstile/get-started/server-side-validation/#error-codes
        // body['error-codes'] = [ ... ]
        ctx.logger.warn('turnstile error', {
          headers: res.headers,
          statusCode: res.statusCode,
          body
        });

        // https://docs.turnstile.com/#siteverify-error-codes-table
        const err = Boom.badRequest(
          ctx.translate
            ? ctx.translate('TURNSTILE_NOT_VERIFIED')
            : 'Turnstile not verified.'
        );
        err.is_turnstile = true;
        ctx.throw(err);
        return;
      }

      return next();
    } catch (err) {
      // this indicates an HTTP error or error while parsing JSON response
      // (e.g. in case the turnstile service goes down)
      ctx.logger.fatal(err);
      return next();
    }
  }
}

module.exports = Policies;
