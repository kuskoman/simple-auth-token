import { enc, HmacSHA256 } from "crypto-js";

export const sign = (payload: string, secret: string): string => {
  const mac = HmacSHA256(payload, secret);
  const macInBase64 = enc.Base64.stringify(mac);

  return macInBase64;
};

export const encode = (
  payload: object,
  secret: string,
  expiry: number = 3600,
  refreshTime: number = 604800
): string => {
  if (secret === undefined || secret === "") {
    throw new Error("Secret can't be empty");
  }

  const stringifiedClaims = JSON.stringify(claims(expiry, refreshTime));
  const stringifiedPayload = JSON.stringify(payload);
  const encodedPayload = Buffer.from(stringifiedPayload).toString("base64");
  const encodedClaims = Buffer.from(stringifiedClaims).toString("base64");
  const encodedContent = encodedClaims + "." + encodedPayload;
  const contentSign = sign(encodedContent, secret);

  return encodedContent + "." + contentSign;
};

export const verify = (token: string, secret: string): boolean => {
  const [claims, payload, originalSign] = token.split(".");
  const content = claims + "." + payload;
  const validSign = sign(content, secret);

  return validSign === originalSign;
};

export const refresh = (
  token: string,
  secret: string,
  expiry: number = 3600,
  refreshTime: number = 604800
): string => {
  if (!verify(token, secret)) {
    throw new Error("Invalid signature");
  }

  const tokenParts = token.split(".");
  const [encodedClaims, encodedPayload] = tokenParts;
  const stringifiedClaims = Buffer.from(encodedClaims, "base64").toString(
    "utf-8"
  );

  const claims = JSON.parse(stringifiedClaims);

  if (!checkIfTokenCanBeRefreshed(claims)) {
    throw new Error("Token can't be refreshed");
  }

  const decodedJsonPayload = Buffer.from(encodedPayload, "base64").toString(
    "utf-8"
  );
  const payload = JSON.parse(decodedJsonPayload);

  return encode(payload, secret, expiry, refreshTime);
};

export const decode = (token: string, secret: string): object => {
  if (!verify(token, secret)) {
    throw new Error("Invalid signature");
  }

  const tokenParts = token.split(".");
  const [encodedClaims, encodedPayload] = tokenParts;

  if (!validate(encodedClaims)) {
    throw new Error("Invalid token");
  }

  const decodedJson = Buffer.from(encodedPayload, "base64").toString("utf-8");

  return JSON.parse(decodedJson);
};

export const validate = (claimsSegment: string): boolean => {
  const stringifiedClaims = Buffer.from(claimsSegment, "base64").toString(
    "utf-8"
  );
  const claims = JSON.parse(stringifiedClaims);

  return checkTokenExpiration(claims);
};

const checkTokenExpiration = (claims: Claims): boolean => {
  const currentUnixTimestamp = ~~(Date.now() / 1000);

  return claims.exp >= currentUnixTimestamp;
};

const checkIfTokenCanBeRefreshed = (claims: Claims): boolean => {
  const currentUnixTimestamp = ~~(Date.now() / 1000);

  return claims.rbt >= currentUnixTimestamp;
};

const claims = (expiry: number, refreshTime: number): Claims => {
  const currentUnixTimestamp = ~~(Date.now() / 1000);

  const claims = {
    iat: currentUnixTimestamp,
    exp: currentUnixTimestamp + expiry,
    rbt: currentUnixTimestamp + refreshTime
  };

  return claims;
};

interface Claims {
  iat: number;
  exp: number;
  rbt: number;
}
