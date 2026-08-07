//! JWT session tokens (HS256) — Rust port of MeterGate's auth.JWTManager.

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Claims {
    pub uid: i64,
    pub username: String,
    pub iss: String,
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
}

pub struct JwtManager {
    secret: String,
}

impl JwtManager {
    pub fn new(secret: &str) -> Self {
        Self { secret: secret.to_string() }
    }

    /// Sign a session token (24h TTL).
    pub fn sign(&self, uid: i64, username: &str) -> Result<String, String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs() as usize;
        let claims = Claims {
            uid,
            username: username.to_string(),
            iss: "stargate".into(),
            aud: "stargate-portal".into(),
            exp: now + 24 * 3600,
            iat: now,
        };
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )
        .map_err(|e| e.to_string())
    }

    /// Verify a session token, returning the claims.
    pub fn verify(&self, token: &str) -> Result<Claims, String> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&["stargate"]);
        validation.set_audience(&["stargate-portal"]);
        validation.validate_exp = true;
        let data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &validation,
        )
        .map_err(|e| e.to_string())?;
        Ok(data.claims)
    }
}
