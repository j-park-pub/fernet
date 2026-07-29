#' Decrypt a token trying multiple keys
#'
#' Attempts to decrypt a Fernet token using each key in `keys`, in order,
#' returning the plaintext from the first key that succeeds. This supports
#' key rotation: pass the current key(s) alongside retired ones so that
#' tokens encrypted under an older key can still be decrypted.
#'
#' @param keys A character vector of base64url-encoded 256-bit Fernet keys,
#'   tried in order until one successfully decrypts `token`.
#' @param token A character string containing the base64url-encoded Fernet
#'   token to decrypt.
#' @param ttl Optional time-to-live in seconds. If supplied, decryption
#'   fails if the token is older than `ttl` seconds. Passed through to
#'   [decrypt()].
#'
#' @return A character string containing the decrypted plaintext.
#' 
#' @export
#'
#' @examples
#' old_key <- generate_key()
#' new_key <- generate_key()
#' token <- encrypt(old_key, "hello world")
#' decrypt_multi(c(new_key, old_key), token)
decrypt_multi <- function(keys, token, ttl = NULL) {
  for (key in keys) {
    result <- tryCatch(decrypt(key, token, ttl = ttl), error = \(e) NULL)
    if (!is.null(result)) return(result)
  }
  stop("Unable to decrypt token with any provided key.")
}