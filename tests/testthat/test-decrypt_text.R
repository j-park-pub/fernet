testthat::test_that("decrypt should return the original content unaltered", {
  og_msg <- "hello"

  key <- generate_key()
  token <- encrypt(key, og_msg)
  decrypt_msg <- decrypt(key, token)

  testthat::expect_equal(decrypt_msg, og_msg)
})

testthat::test_that("decrypt should reject tokens that are older then the ttl specified and decrypt tokens that are not", {
  og_msg <- "hello"

  key <- generate_key()
  token <- encrypt(key, og_msg)
  Sys.sleep(5)

  testthat::expect_error(decrypt(key, token, ttl = 2))
  testthat::expect_no_error(decrypt(key, token, ttl = 100))
})
