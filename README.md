# [**@ladjs/policies**](https://github.com/ladjs/policies)

[![build status](https://img.shields.io/travis/ladjs/policies.svg)](https://travis-ci.org/ladjs/policies)
[![code coverage](https://img.shields.io/codecov/c/github/ladjs/policies.svg)](https://codecov.io/gh/ladjs/policies)
[![code style](https://img.shields.io/badge/code_style-XO-5ed9c7.svg)](https://github.com/sindresorhus/xo)
[![styled with prettier](https://img.shields.io/badge/styled_with-prettier-ff69b4.svg)](https://github.com/prettier/prettier)
[![made with lass](https://img.shields.io/badge/made_with-lass-95CC28.svg)](https://lass.js.org)
[![license](https://img.shields.io/github/license/ladjs/policies.svg)](<>)

> Policies helper for Lad


## Table of Contents

* [Install](#install)
* [Usage](#usage)
* [Options](#options)
* [Contributors](#contributors)
* [License](#license)


## Install

[npm][]:

```sh
npm install @ladjs/policies
```

[yarn][]:

```sh
yarn add @ladjs/policies
```


## Usage

```js
const Policies = require('@ladjs/policies');

const appName = 'My App Name';

const policies = new Policies({ appName }, api_token => Users.findOne({ api_token }));
```


## Options

See [index.js](index.js) for full usage and methods, but at a glance here are the default options:

* `hasVerifiedEmail` (String) - defaults to `has_verified_email` and is the name of the Boolean field on the user object to denote whether or not a user has verified their email address.  Set this to `false`, `null`, `undefined`, or an empty string if you wish to disable this feature.  If a user does not have a verified email address, then they will be redirected to the `verifyRoute` and flashed a message.
* `verifyRoute` (String) - defaults to `/verify` and is the route a user will be redirected to verify their email address
* `verifyRouteHasLocale` (Boolean) - defaults to `true`, and supports `/:locale//` prefix for the `verifyRoute` if `@ladjs/i18n` middleware functions are detected as being used
* `loginRoute` (String) - defaults to `/login` and is the route a user will be redirected to if they need to log in
* `schemeName` (String) - defaults to `null`, but if set as a String it will be used for 401 Unauthorized error scheme name via `Boom.unauthorized(message, schemeName)` internally


## Contributors

| Name               | Website                    |
| ------------------ | -------------------------- |
| **Nick Baugh**     | <http://niftylettuce.com>  |
| **Spencer Snyder** | <http://spencersnyder.io/> |
| **Pablo Varela**   | <http://pablo.life>        |


## License

[MIT](LICENSE) © [Nick Baugh](http://niftylettuce.com)


## 

[npm]: https://www.npmjs.com/

[yarn]: https://yarnpkg.com/
