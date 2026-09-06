#!/usr/bin/env node
// `npm run dev:mock` — Next dev server plus the mock engine, one command.
//
// Spawns both children, prefixes their output, and takes them both down on
// Ctrl-C or if either exits. Deliberately dependency-free: adding
// concurrently/npm-run-all to ship a dev convenience isn't worth the install.

import { spawn } from "node:child_process"

const children = []
let shuttingDown = false

function run(name, cmd, args, env = {}) {
  const child = spawn(cmd, args, {
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  })
  const prefix = `[${name}]`
  const pipe = (stream, to) => {
    let buf = ""
    stream.on("data", (chunk) => {
      buf += chunk
      const lines = buf.split("\n")
      buf = lines.pop() ?? ""
      for (const line of lines) to.write(`${prefix} ${line}\n`)
    })
  }
  pipe(child.stdout, process.stdout)
  pipe(child.stderr, process.stderr)
  child.on("exit", (code, signal) => {
    if (shuttingDown) return
    console.log(`${prefix} exited (${signal ?? code}) — stopping the other process`)
    shutdown(code ?? 1)
  })
  children.push(child)
  return child
}

function shutdown(code) {
  if (shuttingDown) return
  shuttingDown = true
  for (const c of children) {
    if (!c.killed) c.kill("SIGTERM")
  }
  // Give them a moment to close listeners before the parent goes.
  setTimeout(() => process.exit(code), 300)
}

process.on("SIGINT", () => shutdown(0))
process.on("SIGTERM", () => shutdown(0))

// MOCK_ENGINE is not read by anything in src/ — the app just talks to whatever
// is on ENGINE_URL. It is set so `printenv` in a confused dev shell makes the
// situation obvious, and so a future check can assert on it.
run("mock ", process.execPath, ["mocks/engine.mjs"])
run("next ", process.execPath, ["node_modules/.bin/next", "dev", "-p", "9120"], {
  MOCK_ENGINE: "1",
  ENGINE_URL: process.env.ENGINE_URL ?? "http://127.0.0.1:9119",
})
