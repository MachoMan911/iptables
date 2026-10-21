/**
 * 等保三级：RSA-2048 (PKCS#1 v1.5 随机非零填充) + 一次性挑战码前端加密模块
 * 保护登录页面的账号与密码，在 HTTP 模式下抓包与 F12 均不暴露任何账号或密码明文
 */

export function modPowBigInt(base, exp, mod) {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) {
      result = (result * b) % mod;
    }
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}

export function rsaEncryptPkcs1v15(plainText, rsaModulusHex, rsaExponentHex) {
  const encoder = new TextEncoder();
  const msgBytes = encoder.encode(plainText);
  const k = 256; // 2048-bit RSA = 256 bytes
  if (msgBytes.length > k - 11) {
    throw new Error("待加密数据过长");
  }
  const psLen = k - 3 - msgBytes.length;
  const em = new Uint8Array(k);
  em[0] = 0x00;
  em[1] = 0x02;
  const rnd = new Uint8Array(psLen);
  window.crypto.getRandomValues(rnd);
  for (let i = 0; i < psLen; i++) {
    let byte = rnd[i];
    while (byte === 0) {
      const single = new Uint8Array(1);
      window.crypto.getRandomValues(single);
      byte = single[0];
    }
    em[2 + i] = byte;
  }
  em[2 + psLen] = 0x00;
  em.set(msgBytes, 3 + psLen);

  let mHex = "";
  for (let i = 0; i < em.length; i++) {
    mHex += em[i].toString(16).padStart(2, "0");
  }
  const m = BigInt("0x" + mHex);
  const n = BigInt("0x" + rsaModulusHex);
  const e = BigInt("0x" + rsaExponentHex);
  const c = modPowBigInt(m, e, n);
  return c.toString(16).padStart(k * 2, "0");
}

export function encryptLoginCredentials(username, password, challenge) {
  const jsonStr = JSON.stringify({
    username,
    password,
    nonce: challenge.nonce,
    ts: Date.now(),
  });
  return rsaEncryptPkcs1v15(jsonStr, challenge.rsa_n, challenge.rsa_e);
}

export function encryptPasswordPayload(password, challenge) {
  const jsonStr = JSON.stringify({
    password,
    nonce: challenge.nonce,
    ts: Date.now(),
  });
  return rsaEncryptPkcs1v15(jsonStr, challenge.rsa_n, challenge.rsa_e);
}

