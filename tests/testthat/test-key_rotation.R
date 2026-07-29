testthat::test_that("key rotates when given given a the old key and a new key", {
  text <- "hello"
  key <- generate_key()
  token <- encrypt(key, text)

  new_key <- generate_key()
  old_keys <- c(generate_key(), key, generate_key())
  new_token <- rotate_token(old_keys, new_key, token)

  testthat::expect_failure(testthat::expect_equal(new_token, token))
  testthat::expect_no_error(decrypt(new_key, new_token))
  testthat::expect_error(decrypt(key, new_token))
})
