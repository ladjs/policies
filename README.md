# [**@ladjs/policies**](https://github.com/ladjs/policies)

[![build status](https://github.com/ladjs/policies/actions/workflows/ci.yml/badge.svg)](https://github.com/ladjs/policies/actions/workflows/ci.yml)
[![code style](https://img.shields.io/badge/code_style-XO-5ed9c7.svg)](https://github.com/sindresorhus/xo)
[![styled with prettier](https://img.shields.io/badge/styled_with-prettier-ff69b4.svg)](https://github.com/prettier/prettier)
[![made with lass](https://img.shields.io/badge/made_with-lass-95CC28.svg)](https://lass.js.org)
[![license](https://img.shields.io/github/license/ladjs/policies.svg)]()

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


## Usage

```js
const Policies = require('@ladjs/policies');

const appName = 'My App Name';

const policies = new Policies({ appName }, api_token => Users.findOne({ api_token }));
```


## Options

See [index.js](index.js) for options and defaults.


## Contributors

| Name               | Website                           |
| ------------------ | --------------------------------- |
| **Nick Baugh**     | <http://niftylettuce.com>         |
| **Spencer Snyder** | <http://spencersnyder.io/>        |
| **Pablo Varela**   | <http://pablo.life>               |
| **Shaun Warman**   | <https://shaunwarman.com/>        |
| **shadowgate15**   | <https://github.com/shadowgate15> |


## License

[MIT](LICENSE) © [Nick Baugh](http://niftylettuce.com)


##

[npm]: https://www.npmjs.com/
