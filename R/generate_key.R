
#' Generate a Fernet key
#'
#' Generates a random 256-bit key suitable for use with Fernet symmetric
#' encryption, encoded as a URL-safe base64 string.
#'
#' @return A character string containing the URL-safe base64-encoded key.
#' @export
#'
#' @examples
#' generate_key()
generate_key <- function () {
  random_bytes <- openssl::rand_bytes(32)
  b64 <- openssl::base64_encode(random_bytes)
  b64 <- chartr("+/", "-_", b64)
  return(b64)
}