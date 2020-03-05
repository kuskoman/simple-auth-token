import { decode, encode, refresh, sign, validate, verify } from "../src";

describe("Simple Auth Token", () => {
  const secret = "secretkey";

  describe("sign", () => {
    it("should hash two different payloads into different hashes", () => {
      const firstBase64Payload =
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
      const secondBase64Payload =
        "eyJzdWIiOiIxMjM4OTAiLCJuYW1lIjoiSm9obmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
      const firstSign = sign(firstBase64Payload, secret);
      const secondSign = sign(secondBase64Payload, secret);

      expect(firstSign).not.toEqual(secondSign);
    });
  }),
    describe("encode", () => {
      const payload = {
        userId: 2115
      };
      const encodedToken = encode(payload, secret);
      const encodedTokenParts = encodedToken.split(".");
      const encodedPayload = encodedTokenParts[1];

      it("should encode payload", () => {
        const decodedPayload = Buffer.from(encodedPayload, "base64").toString(
          "utf-8"
        );
        const parsedPayload = JSON.parse(decodedPayload);

        expect(parsedPayload).toEqual(payload);
      });

      it("should sign payload", () => {
        const claimsTokenPart = encodedTokenParts[0];
        const signTokenPart = encodedTokenParts[2];
        const validSign = sign(claimsTokenPart + "." + encodedPayload, secret);

        expect(signTokenPart).toEqual(validSign);
      });

      describe("when secret is missing", () => {
        it("throws an exception", () => {
          expect(() => encode(payload, "")).toThrow("Secret can't be empty");
        });
      });
    });

  describe("verify", () => {
    const claims = "ewogIGV4cDogImtpZWR5xZsiCn0=";
    const payload = "aG9sYSBtdW5kbw==";
    const content = claims + "." + payload;

    it("returns true when token has valid sign", () => {
      const validSign = sign(content, secret);
      const token = content + "." + validSign;

      expect(verify(token, secret)).toBeTruthy();
    });

    it("returns false when token has invalid sign", () => {
      const invalidSign = "dadadadadada";
      const token = payload + "." + invalidSign;

      expect(verify(token, secret)).toBeFalsy;
    });
  });

  describe("decode", () => {
    const payload = {
      userId: 2137
    };

    it("decodes valid token", () => {
      const validToken = encode(payload, secret);
      const decodedToken = decode(validToken, secret);

      expect(decodedToken).toEqual(payload);
    });

    it("throws error when token is not valid", () => {
      const invalidToken =
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0Ijo.xNTE2MjM5MDIyfQ";

      expect(() => decode(invalidToken, secret)).toThrow("Invalid signature");
    });

    it("throws exception when token is outdated", () => {
      const outdatedToken = encode(payload, secret, -100);

      expect(() => decode(outdatedToken, secret)).toThrow("Invalid token");
    });
  });

  describe("validate", () => {
    const payload = {
      userName: "andrzej"
    };

    it("returns false when token is outdated", () => {
      const token = encode(payload, secret, -10);

      expect(validate(token)).toEqual(false);
    });

    it("returns true when token is not outdated", () => {
      const token = encode(payload, secret, 10000);

      expect(validate(token)).toEqual(true);
    });
  });

  describe("refresh", () => {
    const payload = {
      userName: "andrzej"
    };

    it("should allow to refresh token what refresh before time claim is not outdated", () => {
      const token = encode(payload, secret);
      const refreshedToken = refresh(token, secret);
      const decodedRefreshedToken = decode(refreshedToken, secret);

      expect(decodedRefreshedToken).toEqual(payload);
    });

    it("should disallow to refresh token after refresh before time claim expires", () => {
      const token = encode(payload, secret, 1000, -3000);

      expect(() => refresh(token, secret)).toThrow("Token can't be refreshed");
    });
  });
});
