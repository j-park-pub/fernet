#' Decrypt a Fernet token
#'
#' Decrypts a Fernet token, verifying its version byte and HMAC signature
#' before decrypting the ciphertext with AES-CBC and removing PKCS7 padding.
#'
#' @param key A character string containing a URL-safe base64-encoded Fernet
#'   key, as produced by [generate_key()]. Must decode to 32 bytes.
#' @param token A character string containing a URL-safe base64-encoded
#'   Fernet token, as produced by [encrypt()].
#' @param ttl Optional numeric time-to-live, in seconds. If supplied, the
#'   token's embedded timestamp is checked and an error is raised if the
#'   token has expired.
#'
#' @return A character string containing the decrypted plaintext message.
#' @export
#'
#' @examples
#' key <- generate_key()
#' token <- encrypt(key, "hello world")
#' decrypt(key, token)
decrypt <- function(key, token, ttl = NULL) {

  token_bytes <- decode_b64url(token)
  key_bytes <- decode_b64url(key)

  if (length(key_bytes) != 32) {
    stop("Invalid key: too short to be a valid Fernet key")
  }

  # signing key is first 128 bits, encryption key is the last 128 bits
  signing_key <- key_bytes[1:16]
  encryption_key <- key_bytes[17:32]

  n <- length(token_bytes)

  # minimum length: 1 (version) + 8 (timestamp) + 16 (iv) + 32 (hmac) + 16 (at least one ciphertext block)
  if (n < 73) {
    stop("Invalid token: too short to be a valid Fernet token")
  }

  # needs to a multiple of 16 to be a valid ciphertext block
  if ((n - 57) %% 16 != 0) {
    stop("Invalid token: ciphertext length is not a multiple of the AES block size")
  }

  version <- token_bytes[1] # first 8 bits (1 byte)
  ts_bytes <- token_bytes[2:9] # 64 bits (8 bytes)
  iv <- token_bytes[10:25] # 128 bits (16 bytes)
  ciphertext <- token_bytes[26:(n-32)] # var length. multiple of 128 bits (16 bytes). stop before you reach the last 32 bytes
  hmac_recv <- token_bytes[(n-31):n] # 256 bits (32 bytes)

  if (version != as.raw(0x80)) {
    stop("Invalid token: unsupported version byte")
  }

  if (!is.null(ttl)){
    # we multiply the acc by 256 to make room for the new value. bit shifting
    token_ts <- Reduce(\(acc, byte) acc * 256 + byte, as.numeric(ts_bytes), 0)
    if (as.numeric(Sys.time()) - token_ts > ttl) {
      stop("The token has expired")
    }
  }

  # verify HMAC (make sure message has not been tampered with)

  # the hmac is a combo of all the fields plus the signed key (first 128 bits of the full farnet key)
  hmac_fields <- c(version, ts_bytes, iv, ciphertext)
  hmac_computed <- digest::hmac(signing_key, hmac_fields, algo = "sha256", raw = TRUE)

  if(!hmac_check(hmac_computed, hmac_recv)){
    stop("This message has been tampered with or corrupted")
  }

  # get the og message

  # encryption key is the last 128 bits of the farnet key
  aes <- digest::AES(encryption_key, mode = "CBC", IV = iv)
  padded_plaintext <- aes$decrypt(ciphertext, raw = TRUE)

  # the length is padded to a multiple of 128 bits (16 bytes). needs to be removed
  pad_len <- as.integer(padded_plaintext[length(padded_plaintext)])
  plaintext_raw <- padded_plaintext[1:(length(padded_plaintext) - pad_len)]

  # decrypted
  rawToChar(plaintext_raw)
}