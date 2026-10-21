package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"sync"
	"time"

	"wallfacer-forwarder/internal/config"
)

var (
	rsaPrivateKey *rsa.PrivateKey
	rsaModulusHex string
	rsaExpHex     string

	challengeMu    sync.Mutex
	challengeStore = make(map[string]time.Time)
)

func init() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("生成 RSA-2048 密钥对失败: %v", err))
	}
	rsaPrivateKey = key
	rsaModulusHex = fmt.Sprintf("%x", key.PublicKey.N)
	rsaExpHex = fmt.Sprintf("%x", big.NewInt(int64(key.PublicKey.E)))
}

// IssueChallenge 签发等保三级防重放一次性挑战码 (Nonce) 及 RSA-2048 公钥参数
func IssueChallenge() map[string]string {
	challengeMu.Lock()
	defer challengeMu.Unlock()

	now := time.Now()
	for k, exp := range challengeStore {
		if exp.Before(now) {
			delete(challengeStore, k)
		}
	}

	b := make([]byte, 16)
	_, _ = rand.Read(b)
	nonce := hex.EncodeToString(b)
	challengeStore[nonce] = now.Add(3 * time.Minute)

	return map[string]string{
		"nonce":     nonce,
		"rsa_n":     rsaModulusHex,
		"rsa_e":     rsaExpHex,
		"algorithm": "RSA-2048-PKCS1v15",
	}
}

// ConsumeChallenge 校验并销毁一次性挑战码（用后即焚，防止抓包重放攻击）
func ConsumeChallenge(nonce string) error {
	challengeMu.Lock()
	defer challengeMu.Unlock()

	exp, ok := challengeStore[nonce]
	delete(challengeStore, nonce)
	if !ok || time.Now().After(exp) {
		return errors.New("安全挑战码已过期或无效，请刷新重试")
	}
	return nil
}

// DecryptLoginCredentials 解密前端整体加密的 {username, password, nonce}
func DecryptLoginCredentials(cipherHex string, expectedNonce string) (string, string, error) {
	cipherBytes, err := hex.DecodeString(strings.TrimSpace(cipherHex))
	if err != nil {
		return "", "", errors.New("登录凭证密文格式无效")
	}
	plainBytes, err := rsa.DecryptPKCS1v15(rand.Reader, rsaPrivateKey, cipherBytes)
	if err != nil {
		return "", "", errors.New("登录凭证 RSA-2048 解密失败")
	}
	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Nonce    string `json:"nonce"`
	}
	if err := json.Unmarshal(plainBytes, &payload); err != nil {
		return "", "", errors.New("登录载荷解析失败")
	}
	if payload.Nonce != expectedNonce {
		return "", "", errors.New("防重放挑战码校验不匹配")
	}
	username := strings.TrimSpace(payload.Username)
	if username == "" || payload.Password == "" {
		return "", "", errors.New("账号或密码不能为空")
	}
	return username, payload.Password, nil
}

// DecryptPasswordCipher 解密前端加密的口令密文
func DecryptPasswordCipher(cipherHex string, expectedNonce string) (string, error) {
	cipherBytes, err := hex.DecodeString(strings.TrimSpace(cipherHex))
	if err != nil {
		return "", errors.New("口令密文格式无效")
	}
	plainBytes, err := rsa.DecryptPKCS1v15(rand.Reader, rsaPrivateKey, cipherBytes)
	if err != nil {
		return "", errors.New("口令密文解密失败")
	}
	var payload struct {
		Password string `json:"password"`
		Nonce    string `json:"nonce"`
	}
	if err := json.Unmarshal(plainBytes, &payload); err != nil {
		return "", errors.New("口令载荷解析失败")
	}
	if payload.Nonce != expectedNonce || payload.Password == "" {
		return "", errors.New("挑战码不匹配或口令为空")
	}
	return payload.Password, nil
}

var (
	reUpper   = regexp.MustCompile(`[A-Z]`)
	reLower   = regexp.MustCompile(`[a-z]`)
	reDigit   = regexp.MustCompile(`\d`)
	reSpecial = regexp.MustCompile(`[^A-Za-z0-9\s]`)
)

// ValidateGrade3Password 校验网络安全等级保护三级（GB/T 22239-2019）口令复杂度
func ValidateGrade3Password(password string, username string) error {
	if len(password) < 8 || len(password) > 64 {
		return errors.New("密码长度必须为 8 ~ 64 位（等保三级要求）")
	}
	if !reUpper.MatchString(password) || !reLower.MatchString(password) ||
		!reDigit.MatchString(password) || !reSpecial.MatchString(password) {
		return errors.New("密码必须同时包含大写字母、小写字母、数字和特殊字符（等保三级要求）")
	}
	if username != "" && strings.Contains(strings.ToLower(password), strings.ToLower(username)) {
		return errors.New("密码不能包含账号名称（等保三级要求）")
	}
	for i := 0; i+3 < len(password); i++ {
		if password[i] == password[i+1] && password[i] == password[i+2] && password[i] == password[i+3] {
			return errors.New("密码不能包含连续 4 个及以上相同字符（等保三级要求）")
		}
	}
	return nil
}

// pbkdf2SHA256 标准库实现的 PBKDF2-HMAC-SHA256
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)

	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)

		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}

// HashPassword 生成与 Python 版本完全兼容的 pbkdf2_sha256$<salt>$<hex> 密码哈希
func HashPassword(password string, salt string) string {
	if salt == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		salt = hex.EncodeToString(b)
	}
	dk := pbkdf2SHA256([]byte(password), []byte(salt), 260000, 32)
	return fmt.Sprintf("pbkdf2_sha256$%s$%s", salt, hex.EncodeToString(dk))
}

func VerifyPassword(plainPassword, storedHash string) bool {
	parts := strings.SplitN(storedHash, "$", 3)
	if len(parts) != 3 || parts[0] != "pbkdf2_sha256" {
		return false
	}
	expected := HashPassword(plainPassword, parts[1])
	return subtle.ConstantTimeCompare([]byte(expected), []byte(storedHash)) == 1
}

// CreateAccessToken 签发 HS256 JWT Token
func CreateAccessToken(username string) (string, error) {
	headerJSON := `{"alg":"HS256","typ":"JWT"}`
	now := time.Now().UTC()
	exp := now.Add(time.Duration(config.Global.Server.JWTExpireHours) * time.Hour)
	payloadMap := map[string]interface{}{
		"sub": username,
		"iat": now.Unix(),
		"exp": exp.Unix(),
	}
	payloadBytes, _ := json.Marshal(payloadMap)

	hEnc := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	pEnc := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := hEnc + "." + pEnc

	mac := hmac.New(sha256.New, []byte(config.Global.Server.JWTSecret))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig, nil
}

// VerifyAccessToken 校验 HS256 JWT Token 并返回用户名
func VerifyAccessToken(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("无效的登录凭证")
	}
	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(config.Global.Server.JWTSecret))
	mac.Write([]byte(signingInput))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(expectedSig)) != 1 {
		return "", errors.New("无效的登录凭证签名")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("凭证载荷解析失败")
	}
	var claims struct {
		Sub string `json:"sub"`
		Exp int64  `json:"exp"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil || claims.Sub == "" {
		return "", errors.New("凭证内容无效")
	}
	if time.Now().UTC().Unix() > claims.Exp {
		return "", errors.New("登录会话已过期，请重新登录")
	}
	return claims.Sub, nil
}

