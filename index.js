const auth = require('basic-auth');
const Boom = require('boom');

function Policies(config) {
  const Users = config.Users;
  const appName = config.appName;

  const ensureLoggedIn = function(ctx, next) {
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
  };

  const ensureApiToken = async function(ctx, next) {
    const credentials = auth(ctx.req);

    if (
      typeof credentials === 'undefined' ||
      typeof credentials.name !== 'string' ||
      !credentials.name
    )
      return ctx.throw(
        Boom.unauthorized(ctx.translate('INVALID_API_CREDENTIALS'), appName)
      );

    const user = await Users.findOne({ api_token: credentials.name });

    if (!user)
      return ctx.throw(
        Boom.unauthorized(ctx.translate('INVALID_API_TOKEN'), appName)
      );

    await ctx.login(user, { session: false });

    return next();
  };

  const ensureLoggedOut = async function(ctx, next) {
    if (ctx.isAuthenticated()) return ctx.redirect('/');
    await next();
  };

  const ensureAdmin = async function(ctx, next) {
    if (!ctx.isAuthenticated() || ctx.state.user.group !== 'admin')
      return ctx.throw(Boom.unauthorized(ctx.translate('IS_NOT_ADMIN')));
    await next();
  };

  return {
    ensureLoggedIn,
    ensureLoggedOut,
    ensureAdmin,
    ensureApiToken
  };
}

module.exports = Policies;
