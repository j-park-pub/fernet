testthat::test_that("encrypt returns a fernet token that is encrypted with the key given in UTF-8", {
  key <- generate_key()
  token <- encrypt(key, "hello")
  token_bytes <- decode_b64url(token)

  testthat::expect_true(length(token_bytes) >= 73)
  testthat::expect_true(length(token_bytes) - 57 %% 16 != 0)
  testthat::expect_equal(token_bytes[1], as.raw(0x80))
})
