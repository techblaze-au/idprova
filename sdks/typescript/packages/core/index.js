// Platform-resolving loader for @idprova/core native bindings.
//
// Detects the host platform/arch/libc and loads the matching
// `@idprova/core-<platform>` package (published separately). During local
// development it prefers a co-located `idprova.<triple>.node` produced by
// `napi build --platform`, so tests run against a fresh local build.

const { existsSync } = require('fs');
const { join } = require('path');

const { platform, arch } = process;

function isMusl() {
  if (platform !== 'linux') return false;
  // napi-standard detection: glibc runtime version is absent on musl (Alpine).
  const report =
    typeof process.report?.getReport === 'function' ? process.report.getReport() : null;
  return !!report && !!report.header && report.header.glibcVersionRuntime == null;
}

function resolveTriple() {
  switch (platform) {
    case 'win32':
      if (arch === 'x64') return 'win32-x64-msvc';
      break;
    case 'darwin':
      if (arch === 'arm64') return 'darwin-arm64';
      break;
    case 'linux':
      if (arch === 'x64') return isMusl() ? 'linux-x64-musl' : 'linux-x64-gnu';
      if (arch === 'arm64') return 'linux-arm64-gnu';
      break;
  }
  return null;
}

function loadBinding() {
  const triple = resolveTriple();
  if (!triple) {
    throw new Error(`@idprova/core: unsupported platform ${platform} ${arch}`);
  }
  // Dev: locally-built binary sitting next to this file.
  const local = join(__dirname, `idprova.${triple}.node`);
  if (existsSync(local)) return require(local);
  // Production: the platform-specific package from npm.
  return require(`@idprova/core-${triple}`);
}

const binding = loadBinding();
const {
  KeyPair,
  Aid,
  AidBuilder,
  Dat,
  Scope,
  TrustLevel,
  ReceiptLog,
  AgentIdentity,
  EvaluationContext,
} = binding;

module.exports.KeyPair = KeyPair;
module.exports.AID = Aid;
module.exports.Aid = Aid;
module.exports.AIDBuilder = AidBuilder;
module.exports.AidBuilder = AidBuilder;
module.exports.DAT = Dat;
module.exports.Dat = Dat;
module.exports.Scope = Scope;
module.exports.TrustLevel = TrustLevel;
module.exports.ReceiptLog = ReceiptLog;
module.exports.AgentIdentity = AgentIdentity;
module.exports.EvaluationContext = EvaluationContext;
