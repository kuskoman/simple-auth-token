# Simple Auth Token

Simple Auth Token is a library inspired by JSON Web Token,
but a lot simpler (and less configurable).

## Usage

**SAT** exports three main methods: _encode_, _decode_ and _refresh_.

### Encode

Encode function takes propeties object as argument.
It has to contain _payload_, which is content you want to
save in token (it must be able to be transformed to JSON),
and _secret_, which is your private secret key, used to sign
the token. You can also use optional parameters: _expiry_,
which is time (in seconds) to token expiration, and _refreshTime_,
(also in seconds) which is maximum time after what the token can't
be refreshed.

Example:

```typescript
import { encode } from "simple-auth-token";

const secret = PROCESS.env.SECRET;

const payload = {
  name: "andrzej",
  surname: "kovalsky"
};

const token = encode({
  payload,
  secret,
  expiry: 3600, // default value
  refreshTime: 86400 // one day
});
```

### Decode

Decode function allows you to decode token created using _encode_ function.
As argument it takes object with _token_ and _secret_ properties.

```typescript
import { decode } from "simple-auth-token";

const decodedToken = decode({ token, secret });
/* if used with code from the example above
it should result with const decodedToken
being copy of payload */
```

### Refresh

Refresh allows you to refresh already created token. The newly
created token should contain same payload as the old one, but you
are able to set different claims for it.

```typescript
import { refresh } from "simple-auth-token";

const refreshedToken = refresh({
  token,
  secret,
  expiry: 2137,
  refreshTime: 0 // can't be refreshed (if time settings aren't changed)
});
```
