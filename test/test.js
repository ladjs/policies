const test = require('ava');

const Policies = require('..');

test.beforeEach(t => {
  t.context.policies = new Policies({}, () => {});
  t.context.redirect = function(url) {
    this.url = url;
  };
});

test('creates Policies', t => {
  const { policies } = t.context;

  t.is(typeof policies, 'object');
});

test('throws TypeError if findByTokenFn is not a function', t => {
  t.throws(() => new Policies({}), {
    instanceOf: TypeError,
    message: 'findByTokenFn must be defined and return a Promise'
  });
});

test('checkVerifiedEmail > returns redirect if not authenticated', async t => {
  const { policies, redirect } = t.context;

  const ctx = {
    isAuthenticated: () => false,
    state: {},
    session: {},
    originalUrl: 'test',
    redirect
  };

  await policies.checkVerifiedEmail(ctx, () => {});

  t.is(ctx.url, '/login');
  t.is(ctx.session.returnTo, 'test');
});

test('checkVerifiedEmail > returns redirect if authenticated', async t => {
  const { policies, redirect } = t.context;

  const ctx = {
    isAuthenticated: () => true,
    state: {
      user: {}
    },
    originalUrl: 'test',
    redirect
  };

  await policies.checkVerifiedEmail(ctx, () => {});

  t.is(ctx.url, '/verify?redirect_to=test');
});

test('checkVerifiedEmail > passes through if path is verifyRoute', async t => {
  const { policies } = t.context;

  const ctx = {
    isAuthenticated: () => true,
    state: {
      user: {}
    },
    path: '/verify'
  };

  await policies.checkVerifiedEmail(ctx, () => {
    t.pass();
  });
});

test('checkVerifiedEmail > returns redirect with req.url and flashes', async t => {
  const { policies, redirect } = t.context;

  const flash = function(_, message) {
    this.flashMessage = message;
  };

  const ctx = {
    isAuthenticated: () => false,
    state: {
      l: message => message
    },
    session: {},
    req: {
      url: 'test'
    },
    translate: message => message,
    redirect,
    flash,
    accepts: () => true
  };

  await policies.checkVerifiedEmail(ctx, () => {});

  t.is(ctx.url, '/login');
  t.is(ctx.session.returnTo, 'test');
  t.is(ctx.flashMessage, 'LOGIN_REQUIRED');
});

test('checkVerifiedEmail > errors when not authenticated and api', async t => {
  const { policies, redirect } = t.context;

  const ctx = {
    isAuthenticated: () => false,
    state: {},
    session: {},
    originalUrl: 'test',
    redirect,
    api: true,
    throw: err => {
      throw err;
    }
  };

  await t.throwsAsync(async () => policies.checkVerifiedEmail(ctx, () => {}), {
    message: 'Please log in to view the page you requested.'
  });
});

test('checkVerifiedEmail > passes through if no hasVerifiedEmail field', async t => {
  const { policies } = t.context;

  policies.config.userFields.hasVerifiedEmail = undefined;

  const ctx = { isAuthenticated: () => true };

  await policies.checkVerifiedEmail(ctx, () => {
    t.pass();
  });
});

test('checkVerifiedEmail > passes through if email has been verified', async t => {
  const { policies } = t.context;

  const ctx = {
    isAuthenticated: () => true,
    state: {
      user: {
        has_verified_email: true
      }
    }
  };

  await policies.checkVerifiedEmail(ctx, () => {
    t.pass();
  });
});

test('checkVerifiedEmail > passes through if pathWithoutLocale is verifyRoute', async t => {
  const { policies } = t.context;

  const ctx = {
    isAuthenticated: () => true,
    state: {
      user: {}
    },
    pathWithoutLocale: '/verify'
  };

  await policies.checkVerifiedEmail(ctx, () => {
    t.pass();
  });
});

test('checkVerifiedEmail > returns redirect if authenticated and flashes', async t => {
  const { policies, redirect } = t.context;

  const flash = function(_, message) {
    this.flashMessage = message;
  };

  const ctx = {
    isAuthenticated: () => true,
    state: {
      l: message => message,
      user: {}
    },
    req: {
      url: 'test'
    },
    accepts: () => true,
    redirect,
    flash
  };

  await policies.checkVerifiedEmail(ctx, () => {});

  t.is(ctx.url, '/verify?redirect_to=test');
});

test('checkVerifiedEmail > errors if email not verified and api', async t => {
  const { policies } = t.context;

  const ctx = {
    isAuthenticated: () => true,
    state: {
      user: {}
    },
    translate: message => message,
    throw: err => {
      throw err;
    },
    api: true
  };

  await t.throwsAsync(async () => policies.checkVerifiedEmail(ctx, () => {}), {
    message: 'EMAIL_VERIFICATION_REQUIRED'
  });
});

test.serial('ensureOtp > passes through if otp is set', async t => {
  const { policies } = t.context;

  process.env.AUTH_OTP_ENABLED = true;

  const ctx = {
    isAuthenticated: () => true,
    state: {
      user: {
        otp_enabled: false
      }
    },
    session: {
      otp: true
    }
  };

  await policies.ensureOtp(ctx, () => {
    t.pass();
  });

  delete process.env.AUTH_OTP_ENABLED;
});

test.serial('ensureOtp > redirects if not authenticated', async t => {
  const { policies, redirect } = t.context;

  process.env.AUTH_OTP_ENABLED = true;

  const ctx = {
    isAuthenticated: () => false,
    state: {
      user: {
        otp_enabled: false
      }
    },
    session: {
      otp: true
    },
    originalUrl: 'test',
    redirect
  };

  await policies.ensureOtp(ctx, () => {});

  t.is(ctx.url, '/otp/login');
  t.is(ctx.session.returnTo, 'test');

  delete process.env.AUTH_OTP_ENABLED;
});

test.serial('ensureOtp > redirects if otp not enabled on user', async t => {
  const { policies, redirect } = t.context;

  process.env.AUTH_OTP_ENABLED = true;

  const flash = function(_, message) {
    this.flashMessage = message;
  };

  const ctx = {
    isAuthenticated: () => true,
    state: {
      l: message => message,
      user: {
        otp_enabled: true
      }
    },
    session: {
      otp: false
    },
    req: {
      url: 'test'
    },
    translate: message => message,
    redirect,
    flash,
    accepts: () => true
  };

  await policies.ensureOtp(ctx, () => {});

  t.is(ctx.url, '/otp/login');
  t.is(ctx.session.returnTo, 'test');
  // t.is(ctx.flashMessage, 'TWO_FACTOR_REQUIRED');

  delete process.env.AUTH_OTP_ENABLED;
});

test('ensureOtp > passes through if OTP not enabled', async t => {
  const { policies } = t.context;

  await policies.ensureOtp({}, () => {
    t.pass();
  });
});

test('ensureLoggedIn > passes through if logged in', async t => {
  const { policies } = t.context;

  const ctx = {
    isAuthenticated: () => true
  };

  policies.checkVerifiedEmail = (_, next) => next();

  await policies.ensureLoggedIn(ctx, () => {
    t.pass();
  });
});

test('ensureLoggedIn > redirects if not authenticated', async t => {
  const { policies, redirect } = t.context;

  const ctx = {
    isAuthenticated: () => false,
    originalUrl: 'test',
    redirect,
    session: {},
    state: {}
  };

  await policies.ensureLoggedIn(ctx, () => {});

  t.is(ctx.url, '/login');
  t.is(ctx.session.returnTo, 'test');
});

test('ensureLoggedIn > errors if api', async t => {
  const { policies, redirect } = t.context;

  const ctx = {
    isAuthenticated: () => false,
    originalUrl: 'test',
    redirect,
    session: {},
    state: {},
    translate: message => message,
    throw: err => {
      throw err;
    },
    api: true
  };

  await t.throwsAsync(() => policies.ensureLoggedIn(ctx, () => {}), {
    message: 'LOGIN_REQUIRED'
  });
});

test('ensureLoggedIn > redirects with flashes', async t => {
  const { policies, redirect } = t.context;

  const flash = function(_, message) {
    ctx.flashMessage = message;
  };

  const ctx = {
    isAuthenticated: () => false,
    req: {
      url: 'test'
    },
    redirect,
    session: {},
    state: {
      l: message => message
    },
    flash,
    accepts: () => true
  };

  await policies.ensureLoggedIn(ctx, () => {});

  t.is(ctx.url, '/login');
  t.is(ctx.session.returnTo, 'test');
  t.is(ctx.flashMessage, 'Please log in to view the page you requested.');
});

test('ensureApiToken > passes through if credentials exist', async t => {
  const { policies } = t.context;

  policies.findByTokenFn = () => {
    return 'foo';
  };

  policies.checkVerifiedEmail = (_, next) => next();

  const ctx = {
    req: {
      headers: {
        authorization: 'basic Zm9vOmJhcg=='
      }
    },
    login: () => {}
  };

  await policies.ensureApiToken(ctx, () => {
    t.pass();
  });
});

test('ensureApiToken > errors if no credentials', async t => {
  const { policies } = t.context;

  const ctx = {
    req: {
      headers: {
        authorization: undefined
      }
    },
    throw: err => {
      throw err;
    }
  };

  await t.throwsAsync(async () => policies.ensureApiToken(ctx, () => {}), {
    message: 'Invalid API credentials.'
  });
});

test('ensureApiToken > errors if no credentials and translate', async t => {
  const { policies } = t.context;

  const ctx = {
    req: {
      headers: {
        authorization: undefined
      }
    },
    throw: err => {
      throw err;
    },
    translate: message => message
  };

  await t.throwsAsync(async () => policies.ensureApiToken(ctx, () => {}), {
    message: 'INVALID_API_CREDENTIALS'
  });
});

test('ensureApiToken > errors if no API token', async t => {
  const { policies } = t.context;

  policies.findByTokenFn = () => {
    return undefined;
  };

  const ctx = {
    req: {
      headers: {
        authorization: 'basic Zm9vOmJhcg=='
      }
    },
    throw: err => {
      throw err;
    }
  };

  await t.throwsAsync(async () => policies.ensureApiToken(ctx, () => {}), {
    message: 'Invalid API token.'
  });
});

test('ensureApiToken > errors if no API token and translate', async t => {
  const { policies } = t.context;

  policies.findByTokenFn = () => {
    return undefined;
  };

  const ctx = {
    req: {
      headers: {
        authorization: 'basic Zm9vOmJhcg=='
      }
    },
    throw: err => {
      throw err;
    },
    translate: message => message
  };

  await t.throwsAsync(async () => policies.ensureApiToken(ctx, () => {}), {
    message: 'INVALID_API_TOKEN'
  });
});

test('ensureLoggedOut > passes through if logged out', async t => {
  const { policies } = t.context;

  const ctx = { isAuthenticated: () => false };

  await policies.ensureLoggedOut(ctx, () => {
    t.pass();
  });
});

test('ensureLoggedOut > redirects if logged in', async t => {
  const { policies, redirect } = t.context;

  const ctx = {
    isAuthenticated: () => true,
    session: {},
    originalUrl: 'test',
    redirect
  };

  await policies.ensureLoggedOut(ctx, () => {});

  t.is(ctx.url, 'back');
  t.is(ctx.session.returnTo, 'test');
});

test('ensureLoggedOut > redirects if logged in and flashes', async t => {
  const { policies, redirect } = t.context;

  const flash = function(_, message) {
    this.flashMessage = message;
  };

  const ctx = {
    isAuthenticated: () => true,
    session: {},
    req: {
      url: 'test'
    },
    redirect,
    flash,
    accepts: () => true
  };

  await policies.ensureLoggedOut(ctx, () => {});

  t.is(ctx.url, 'back');
  t.is(ctx.session.returnTo, 'test');
  t.is(ctx.flashMessage, 'Please log out to view the page you requested.');
});

test('ensureLoggedOut > errors if api', async t => {
  const { policies } = t.context;

  const ctx = {
    isAuthenticated: () => true,
    translate: message => message,
    api: true,
    throw: err => {
      throw err;
    },
    session: {},
    originalUrl: 'test'
  };

  await t.throwsAsync(async () => policies.ensureLoggedOut(ctx, () => {}), {
    message: 'LOGOUT_REQUIRED'
  });
});

test('ensureAdmin > passes through if authenticated and admin', async t => {
  const { policies } = t.context;

  policies.checkVerifiedEmail = (_, next) => next();

  const ctx = {
    isAuthenticated: () => true,
    state: {
      user: {
        group: 'admin'
      }
    }
  };

  await policies.ensureAdmin(ctx, () => {
    t.pass();
  });
});

test('ensureAdmin > errors if authenticate and not admin', async t => {
  const { policies } = t.context;

  const ctx = {
    isAuthenticated: () => false,
    throw: err => {
      throw err;
    }
  };

  await t.throwsAsync(async () => policies.ensureAdmin(ctx, () => {}), {
    message: 'You do not belong to the administrative user group.'
  });
});

test('ensureAdmin > errors if authenticate and not admin and translate', async t => {
  const { policies } = t.context;

  const ctx = {
    isAuthenticated: () => false,
    throw: err => {
      throw err;
    },
    translate: message => message
  };

  await t.throwsAsync(async () => policies.ensureAdmin(ctx, () => {}), {
    message: 'IS_NOT_ADMIN'
  });
});
