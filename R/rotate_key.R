#' Re-encrypt a token under a new key
#'
#' Decrypts `token` using [decrypt_multi()] against one or more candidate
#' `old_keys`, then re-encrypts the resulting plaintext with `new_key`. This
#' supports key rotation: existing tokens can be migrated to a new key
#' without ever needing to store the plaintext.
#'
#' @param old_keys A character vector of base64url-encoded 256-bit Fernet
#'   keys to try when decrypting `token`, in order.
#' @param new_key A base64url-encoded 256-bit Fernet key to encrypt the
#'   recovered plaintext with.
#' @param token A character string containing the base64url-encoded Fernet
#'   token to rotate.
#' @param ttl Optional time-to-live in seconds, passed through to
#'   [decrypt_multi()] when decrypting `token`.
#'
#' @return A character string containing the base64url-encoded Fernet token,
#'   encrypted under `new_key`.
#' @export
#'
#' @examples
#' old_key <- generate_key()
#' new_key <- generate_key()
#' old_keys <- c(old_key, generate_key(), generate_key())
#' token <- encrypt(old_key, "hello world")
#' rotate_token(old_keys, new_key, token)
rotate_token <- function(old_keys, new_key, token, ttl = NULL) {
    plaintext <- decrypt_multi(old_keys, token, ttl)
    new_token <- encrypt(new_key, plaintext)
    return(new_token)
}