name: 'dcrypt'
description: 'extended openssl bindings'
keywords: ['crypt', 'crypto', 'dcrypt', 'openssl']
version: require('fs').readFileSync('./VERSION', 'utf8').trim()
author: 'Jacob Evans <dcrypt@dekz.net>'

licences: [
  type: 'FEISTY'
  url: 'http://github.com/feisty/license/raw/master/LICENSE'
]

contributors: ['Jacob Evans <jacob@dekz.net>']

repository:
  type: 'git'
  url: 'https://github.com/dekz/dcrypt.git'
  private: 'git@github.com:dekz/dcrypt.git'
  web: 'https://github.com/dekz/dcrypt'

bugs:
  mail: 'dcrypt@dekz.net'
  web: 'https://github.com/dekz/dcrypt/issues'

main: './dcrypt.js'
dependencies:
  'coffee-script': '>= 0.9.5 < 1.1.0'

engines:
  node: '>= 0.4.2 < 0.5.0'
  npm: '>= 0.3.15 < 1.1.0'
