//! Github authentication.

// TODO
// let key = gcp_kms_sign::GcpKmsKeyVersion::new(&args.app_private_key).await.unwrap();

//     // Construct JWT as per https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
//     #[derive(serde::Serialize)]
//     struct Claims {
//         iss: String,
//         iat: usize,
//         exp: usize,
//     }
//     let claims = Claims {
//         iss: args.app_client_id,
//         iat: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as usize,
//         exp: (std::time::SystemTime::now() + std::time::Duration::from_secs(args.token_lifetime_seconds as u64)).duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as usize,

//     };
//     let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
//     use base64::Engine;
//     let header_encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
//     let claims_encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
//     let parial_jwt = format!("{}.{}", header_encoded, claims_encoded);

//     let signature = key.asymmetric_sign(parial_jwt.as_bytes()).await.unwrap();

//     let signature_encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature);
//     let jwt = format!("{}.{}", parial_jwt, signature_encoded);

//     println!("JWT: {}", jwt);
