
#' Encrypt data using Fernet
#'
#' Encrypts a message using the Fernet symmetric encryption scheme, producing
#' a URL-safe base64-encoded token that includes a version byte, timestamp,
#' initialization vector, AES-CBC encrypted ciphertext, and an HMAC signature.
#'
#' @param key A character string containing a URL-safe base64-encoded Fernet
#'   key, as produced by [generate_key()]. Must decode to 32 bytes.
#' @param data A raw vector (or object coercible to one) containing the
#'   plaintext data to encrypt.
#'
#' @return A character string containing the URL-safe base64-encoded Fernet
#'   token.
#' @export
#'
#' @examples
#' key <- generate_key()
#' encrypt(key, "hello world")
encrypt <- function(key, data) {
  key_bytes <- decode_b64url(key)
  if (length(key_bytes) != 32) {
    stop("Invalid key: too short to be a valid Fernet key")
  }

  signing_key <- key_bytes[1:16]
  encryption_key <- key_bytes[17:32]
  version <- as.raw(0x80)
  current_timestamp <- as.numeric(lubridate::now(tzone = "UTC"))
  time_bytes <- uint_be(current_timestamp)
  iv <- openssl::rand_bytes(16)
  aes <- digest::AES(encryption_key, mode = "CBC", IV = iv, padding = TRUE)
  encrypted_data <- aes$encrypt(data)

  hmac <- c(version, time_bytes, iv, encrypted_data)
  hmac <- digest::hmac(signing_key, hmac, algo = "sha256", raw = TRUE)

  token <- c(version, time_bytes, iv, encrypted_data, hmac)
  token <- openssl::base64_encode(token)
  token <- chartr("+/", "-_", token)
  return(token)
}