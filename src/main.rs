use axum::{
    extract::{rejection::JsonRejection, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction,
};
use spl_token::instruction as token_instruction;
use std::str::FromStr;
use tower_http::cors::CorsLayer;
use ed25519_dalek::Verifier;
use serde_json::json;
use base64::Engine;

// Custom error type for better error handling
#[derive(Debug, thiserror::Error)]
enum ServerError {
    #[error("Invalid public key: {0}")]
    InvalidPubkey(String),
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),
    #[error("Missing required field: {0}")]
    MissingField(String),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Internal error: {0}")]
    Internal(String),
}

// Standard response format as specified
#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

// Request/Response structs for each endpoint
#[derive(Deserialize)]
struct KeypairRequest {
    // No fields needed for keypair generation
}

#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct AccountMetaResponse {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct InstructionResponse {
    program_id: String,
    accounts: Vec<AccountMetaResponse>,
    instruction_data: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: i64, // allow negative for validation
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

// New response structs for send endpoints as per assignment
#[derive(Serialize)]
struct SendSolResponse {
    program_id: String,
    accounts: Vec<String>, // Just addresses, not AccountMeta objects
    instruction_data: String,
}

#[derive(Serialize)]
struct SendTokenAccountResponse {
    pubkey: String,
    isSigner: bool, // Note: camelCase as per assignment
}

#[derive(Serialize)]
struct SendTokenResponse {
    program_id: String,
    accounts: Vec<SendTokenAccountResponse>,
    instruction_data: String,
}

// Helper function to create error response with HTTP 400
fn error_response<T>(error: &str) -> (StatusCode, Json<ApiResponse<T>>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::<T> {
            success: false,
            data: None,
            error: Some(error.to_string()),
        })
    )
}

// Helper function to create success response with HTTP 200
fn success_response<T>(data: T) -> (StatusCode, Json<ApiResponse<T>>) {
    (
        StatusCode::OK,
        Json(ApiResponse::<T> {
            success: true,
            data: Some(data),
            error: None,
        })
    )
}

// Helper to parse pubkey with better error handling
fn parse_pubkey(pubkey_str: &str) -> Result<Pubkey, ServerError> {
    Pubkey::from_str(pubkey_str).map_err(|_| {
        ServerError::InvalidPubkey(format!("Could not parse pubkey: {}", pubkey_str))
    })
}

// Helper to validate amounts
fn validate_amount(amount: u64, field_name: &str) -> Result<(), ServerError> {
    if amount == 0 {
        return Err(ServerError::InvalidAmount(
            format!("{} must be greater than 0", field_name)
        ));
    }
    Ok(())
}

// Global error handler for JSON parsing/deserialization errors
async fn json_error_handler(err: JsonRejection) -> impl IntoResponse {
    let msg = match &err {
        JsonRejection::MissingJsonContentType(_) => "Missing or invalid Content-Type: application/json".to_string(),
        JsonRejection::JsonDataError(e) => format!("Invalid JSON data: {}", e.body_text()),
        JsonRejection::JsonSyntaxError(e) => format!("Malformed JSON: {}", e.body_text()),
        _ => format!("Invalid request: {}", err),
    };
    let body = serde_json::json!({
        "success": false,
        "error": msg
    });
    (StatusCode::BAD_REQUEST, axum::response::Json(body))
}

// 1. Generate Keypair endpoint
async fn generate_keypair() -> (StatusCode, Json<ApiResponse<KeypairResponse>>) {
    // Generate a new keypair - this is pretty straightforward
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey();
    
    // Convert to base58 strings as required
    let pubkey_str = bs58::encode(pubkey.to_bytes()).into_string();
    let secret_str = bs58::encode(keypair.to_bytes()).into_string();
    
    success_response(KeypairResponse {
        pubkey: pubkey_str,
        secret: secret_str,
    })
}

// 2. Create Token endpoint
async fn create_token(
    Json(request): Json<CreateTokenRequest>,
) -> (StatusCode, Json<ApiResponse<InstructionResponse>>) {
    // Validate inputs
    let mint_authority = match parse_pubkey(&request.mint_authority) {
        Ok(pk) => pk,
        Err(e) => return error_response(&e.to_string()),
    };
    
    let mint = match parse_pubkey(&request.mint) {
        Ok(pk) => pk,
        Err(e) => return error_response(&e.to_string()),
    };
    
    // Validate decimals - SPL tokens support 0-9 decimals
    if request.decimals > 9 {
        return error_response("Decimals must be between 0 and 9");
    }
    
    // Create the initialize mint instruction
    let instruction = match token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority), // freeze authority (optional)
        request.decimals,
    ) {
        Ok(inst) => inst,
        Err(_) => return error_response("Failed to create initialize mint instruction"),
    };
    
    // Convert to our response format
    let accounts = instruction
        .accounts
        .iter()
        .map(|meta| AccountMetaResponse {
            pubkey: meta.pubkey.to_string(),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        })
        .collect();
    
    success_response(InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    })
}

// 3. Mint Token endpoint
async fn mint_token(
    Json(request): Json<MintTokenRequest>,
) -> (StatusCode, Json<ApiResponse<InstructionResponse>>) {
    // Parse and validate all pubkeys
    let mint = match parse_pubkey(&request.mint) {
        Ok(pk) => pk,
        Err(e) => return error_response(&e.to_string()),
    };
    let destination = match parse_pubkey(&request.destination) {
        Ok(pk) => pk,
        Err(e) => return error_response(&e.to_string()),
    };
    let authority = match parse_pubkey(&request.authority) {
        Ok(pk) => pk,
        Err(e) => return error_response(&e.to_string()),
    };
    // Validate amount
    if request.amount <= 0 {
        return error_response("Invalid amount: amount must be greater than 0");
    }
    if request.amount > 1_000_000_000_000_000_000 {
        return error_response("Invalid amount: amount too large");
    }
    let amount = request.amount as u64;
    // Create mint_to instruction
    let instruction = match token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        amount,
    ) {
        Ok(inst) => inst,
        Err(_) => return error_response("Failed to create mint_to instruction"),
    };
    // Convert to response format
    let accounts = instruction
        .accounts
        .iter()
        .map(|meta| AccountMetaResponse {
            pubkey: meta.pubkey.to_string(),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        })
        .collect();
    success_response(InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    })
}

// Wrapper for /token/mint to catch JSON extraction errors
async fn mint_token_wrapper(payload: Result<axum::extract::Json<MintTokenRequest>, axum::extract::rejection::JsonRejection>) -> axum::response::Response {
    match payload {
        Ok(json) => mint_token(json).await.into_response(),
        Err(err) => json_error_handler(err).await.into_response(),
    }
}

// 4. Sign Message endpoint
async fn sign_message(
    Json(request): Json<SignMessageRequest>,
) -> (StatusCode, Json<ApiResponse<SignMessageResponse>>) {
    // Validate inputs
    if request.message.is_empty() {
        return error_response("Message cannot be empty");
    }
    
    if request.secret.is_empty() {
        return error_response("Secret key cannot be empty");
    }
    
    // Parse the secret key
    let secret_bytes = match bs58::decode(&request.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return error_response("Invalid secret key format"),
    };
    
    if secret_bytes.len() != 64 {
        return error_response("Invalid secret key length");
    }
    
    // Create keypair from secret
    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => return error_response("Invalid secret key"),
    };
    
    // Sign the message
    let message_bytes = request.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);
    
    success_response(SignMessageResponse {
        signature: base64::engine::general_purpose::STANDARD.encode(signature.as_ref()),
        public_key: bs58::encode(keypair.pubkey().to_bytes()).into_string(),
        message: request.message,
    })
}

// 5. Verify Message endpoint
async fn verify_message(
    Json(request): Json<VerifyMessageRequest>,
) -> (StatusCode, Json<ApiResponse<VerifyMessageResponse>>) {
    // Parse pubkey
    let pubkey = match parse_pubkey(&request.pubkey) {
        Ok(pk) => pk,
        Err(e) => return error_response(&e.to_string()),
    };
    
    // Parse signature
    let signature_bytes = match base64::engine::general_purpose::STANDARD.decode(&request.signature) {
        Ok(bytes) => bytes,
        Err(_) => return error_response("Invalid signature format"),
    };
    
    if signature_bytes.len() != 64 {
        return error_response("Invalid signature length");
    }
    
    // Create signature object
    let signature = match ed25519_dalek::Signature::from_bytes(&signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return error_response("Invalid signature"),
    };
    
    // Create public key for verification
    let public_key = match ed25519_dalek::PublicKey::from_bytes(&pubkey.to_bytes()) {
        Ok(pk) => pk,
        Err(_) => return error_response("Invalid public key for verification"),
    };
    
    // Verify the signature
    let message_bytes = request.message.as_bytes();
    let is_valid = public_key.verify(message_bytes, &signature).is_ok();
    
    success_response(VerifyMessageResponse {
        valid: is_valid,
        message: request.message,
        pubkey: request.pubkey,
    })
}

// 6. Send SOL endpoint
async fn send_sol(
    Json(request): Json<SendSolRequest>,
) -> (StatusCode, Json<ApiResponse<SendSolResponse>>) {
    // Parse pubkeys
    let from = match parse_pubkey(&request.from) {
        Ok(pk) => pk,
        Err(e) => return error_response(&e.to_string()),
    };
    
    let to = match parse_pubkey(&request.to) {
        Ok(pk) => pk,
        Err(e) => return error_response(&e.to_string()),
    };
    
    // Validate amount
    if let Err(e) = validate_amount(request.lamports, "lamports") {
        return error_response(&e.to_string());
    }
    
    // Additional validation: sender and recipient should be different
    if from == to {
        return error_response("Sender and recipient cannot be the same");
    }
    
    // Create transfer instruction
    let instruction = system_instruction::transfer(&from, &to, request.lamports);
    
    // Convert to assignment-required format: just addresses
    let accounts = instruction
        .accounts
        .iter()
        .map(|meta| meta.pubkey.to_string())
        .collect();
    
    success_response(SendSolResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    })
}

// 7. Send Token endpoint
async fn send_token(
    Json(request): Json<SendTokenRequest>,
) -> (StatusCode, Json<ApiResponse<SendTokenResponse>>) {
    // Parse all pubkeys
    let destination = match parse_pubkey(&request.destination) {
        Ok(pk) => pk,
        Err(e) => return error_response(&e.to_string()),
    };
    
    let mint = match parse_pubkey(&request.mint) {
        Ok(pk) => pk,
        Err(e) => return error_response(&e.to_string()),
    };
    
    let owner = match parse_pubkey(&request.owner) {
        Ok(pk) => pk,
        Err(e) => return error_response(&e.to_string()),
    };
    
    // Validate amount
    if let Err(e) = validate_amount(request.amount, "amount") {
        return error_response(&e.to_string());
    }
    
    // Derive the source token account from owner and mint
    // This is the token account that holds the tokens to be transferred
    let source = spl_associated_token_account::get_associated_token_address(&owner, &mint);
    
    // Create transfer instruction
    let instruction = match token_instruction::transfer(
        &spl_token::id(),
        &source,      // source token account
        &destination, // destination token account
        &owner,       // authority (owner of source account)
        &[],
        request.amount,
    ) {
        Ok(inst) => inst,
        Err(_) => return error_response("Failed to create transfer instruction"),
    };
    
    // Convert to assignment-required format
    let accounts = instruction
        .accounts
        .iter()
        .map(|meta| SendTokenAccountResponse {
            pubkey: meta.pubkey.to_string(),
            isSigner: meta.is_signer, // camelCase as per assignment
        })
        .collect();
    
    success_response(SendTokenResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    })
}

// Health check endpoint
async fn health_check() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::OK, Json(json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "service": "Solana Fellowship Server"
    })))
}

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    // Configure CORS for web frontend
    let cors = CorsLayer::permissive();
    
    // Build the router with all our endpoints
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token_wrapper))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token))
        .layer(cors);
    
    // Start the server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("🚀 Solana Fellowship Server running on http://0.0.0.0:3000");
    println!("📝 Available endpoints:");
    println!("   POST /keypair - Generate new keypair");
    println!("   POST /token/create - Create SPL token");
    println!("   POST /token/mint - Mint tokens");
    println!("   POST /message/sign - Sign message");
    println!("   POST /message/verify - Verify signature");
    println!("   POST /send/sol - Create SOL transfer instruction");
    println!("   POST /send/token - Create token transfer instruction");
    
    axum::serve(listener, app).await.unwrap();
} 