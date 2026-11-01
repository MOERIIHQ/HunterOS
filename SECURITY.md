# HunterOS Security Policy

## Safety First

HunterOS is designed with **safety** as the highest priority principle.

## Core Safety Rules

1. **Safe Mode ON by default** — All destructive actions are blocked
2. **Scope is a technical constraint** — Not just documentation
3. **Unknown targets are NOT automatically testable**
4. **No destructive testing**
5. **No DoS attacks**
6. **No credential theft**
7. **No persistence mechanisms**
8. **No unauthorized access**
9. **No secret exfiltration**
10. **No testing against targets outside scope**

## Target Status

- **IN_SCOPE**: Target is within defined scope
- **OUT_OF_SCOPE**: Target is outside defined scope — BLOCKED
- **UNKNOWN**: Target status unknown — requires REVIEW

## Safe Mode Action Types

| Action Type | Safe Mode ON | Safe Mode OFF |
|-------------|-------------|---------------|
| READ_ONLY   | ALLOWED     | ALLOWED       |
| PASSIVE     | ALLOWED     | ALLOWED       |
| ACTIVE      | REVIEW      | REVIEW        |
| DESTRUCTIVE | BLOCKED     | REVIEW        |

## Policy Decision Flow

```
TARGET → SCOPE CHECK → POLICY CHECK → SAFE MODE CHECK → ACTION DECISION
```

## Reporting

All actions are logged with structured fields including scope status,
policy decision, and Safe Mode state.