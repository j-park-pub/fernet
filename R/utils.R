#' Constant-time comparison of two HMACs
#'
#' Compares two raw HMAC digests for equality using a constant-time
#' (length-then-XOR) comparison to reduce the risk of timing attacks.
#'
#' @param computed A raw vector containing the locally computed HMAC.
#' @param recv A raw vector containing the received HMAC to verify against.
#'
#' @return `TRUE` if the two HMACs are equal, `FALSE` otherwise.
#' @noRd
hmac_check <- function (computed, recv) {
  if (length(computed) != length(recv)) return(FALSE)
  diff <- Reduce(bitwOr, bitwXor(as.integer(computed), as.integer(recv)))
  return(diff == 0L)
}

#' Encode a number as an 8-byte big-endian unsigned integer
#'
#' Converts a numeric value (such as a Unix timestamp) into an 8-byte raw
#' vector in big-endian byte order, as used in the Fernet token format.
#'
#' @param x A non-negative numeric value to encode. Fractional parts are
#'   truncated via [floor()].
#'
#' @return A raw vector of length 8 representing `x` in big-endian order.
#' @noRd
uint_be <- function(x) {
  x <- floor(x)
  bytes <- raw(8)
  for (i in 8:1) {
    bytes[i] <- as.raw(x %% 256)
    x <- x %/% 256
  }
  return(bytes)
}

#' Decode a URL-safe base64 string
#'
#' Converts a URL-safe base64 string (using `-` and `_` in place of `+` and
#' `/`) back to standard base64 and decodes it to raw bytes.
#'
#' @param val A character string containing URL-safe base64-encoded data.
#'
#' @return A raw vector containing the decoded bytes.
#' @noRd
decode_b64url <- function(val) {
  b64 <- chartr("-_", "+/", val)
  openssl::base64_decode(b64)
}