testthat::test_that("generate_key returns a 32 byte UTF-8 encoded string", {
  key <- generate_key()
  key_bytes <- decode_b64url(key)
  
  testthat::expect_equal(length(key_bytes), 32L)
})
