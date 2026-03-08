import type { ParsedScope } from '../types';

/** Parse a 4-part scope string: namespace:protocol:resource:action */
export function parseScope(s: string): ParsedScope {
  const parts = s.split(':');
  if (parts.length !== 4) {
    throw new Error(
      `scope must have 4 parts (namespace:protocol:resource:action), got ${parts.length} parts: ${s}`
    );
  }
  return {
    namespace: parts[0],
    protocol: parts[1],
    resource: parts[2],
    action: parts[3],
  };
}

/** Check if a granted scope covers (permits) a requested scope. */
export function scopeCovers(granted: ParsedScope, requested: ParsedScope): boolean {
  return (
    (granted.namespace === '*' || granted.namespace === requested.namespace) &&
    (granted.protocol === '*' || granted.protocol === requested.protocol) &&
    (granted.resource === '*' || granted.resource === requested.resource) &&
    (granted.action === '*' || granted.action === requested.action)
  );
}

/** Check if a set of granted scope strings permits a requested scope. */
export function scopeSetPermits(grantedStrings: string[], requested: ParsedScope): boolean {
  return grantedStrings.some(s => {
    try {
      const granted = parseScope(s);
      return scopeCovers(granted, requested);
    } catch {
      return false;
    }
  });
}

/** Format a ParsedScope back to string. */
export function scopeToString(scope: ParsedScope): string {
  return `${scope.namespace}:${scope.protocol}:${scope.resource}:${scope.action}`;
}

/** Explain why a scope match succeeded or failed. */
export function explainScopeMatch(
  grantedStrings: string[],
  requestedStr: string
): { permitted: boolean; explanation: string } {
  let requested: ParsedScope;
  try {
    requested = parseScope(requestedStr);
  } catch (e) {
    return { permitted: false, explanation: `Invalid requested scope: ${e}` };
  }

  for (const gs of grantedStrings) {
    let granted: ParsedScope;
    try {
      granted = parseScope(gs);
    } catch {
      continue;
    }
    if (scopeCovers(granted, requested)) {
      const parts = ['namespace', 'protocol', 'resource', 'action'] as const;
      const matches = parts.map(p => {
        if (granted[p] === '*') return `${p}: * (wildcard)`;
        return `${p}: ${granted[p]} = ${requested[p]}`;
      });
      return {
        permitted: true,
        explanation: `Permitted by ${gs}:\n${matches.join('\n')}`,
      };
    }
  }

  return {
    permitted: false,
    explanation: `No granted scope covers ${requestedStr}.\nGranted: [${grantedStrings.join(', ')}]`,
  };
}
