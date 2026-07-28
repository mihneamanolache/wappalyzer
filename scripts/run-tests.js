#!/usr/bin/env node

'use strict'

const fs = require('fs')
const path = require('path')
const { spawnSync } = require('child_process')

const ROOT = path.resolve(__dirname, '..')
const TEST_DIR = path.join(ROOT, 'test')
const files = fs.readdirSync(TEST_DIR)
    .filter((name) => name.endsWith('.test.js'))
    .sort()
    .map((name) => path.join(TEST_DIR, name))

if (!files.length) {
    throw new Error(`No test files found in ${TEST_DIR}`)
}

const result = spawnSync(process.execPath, ['--test', ...files], {
    cwd: ROOT,
    stdio: 'inherit',
})

if (result.error) {
    throw result.error
}

process.exit(result.status === null ? 1 : result.status)

