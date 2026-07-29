testthat::test_that("String is properly codes base64url", {
  key <- "KM75bg4v0obJDxJeJkXHaUgWLssdFQ2h_BzeZOgDQe0="
  key_decoded <- decode_b64url(key)

  testthat::expect_no_error(decode_b64url(key))
  testthat::expect_equal(class(key_decoded), "raw")
})

testthat::test_that("a 8 byte unsigned int is create from big endian value", {
  testthat::expect_no_error(uint_be(1785175392))
  testthat::expect_true(class(uint_be(1785175392)) == "raw")
  testthat::expect_true(length(uint_be(1785175392)) == 8)
})

testthat::test_that("hmac_check returns TRUE for identical HMACs and FALSE for differing ones", {
  mac1 <- as.raw(c(0x01, 0x02, 0x03, 0x04))
  mac2 <- as.raw(c(0x01, 0x02, 0x03, 0x04))
  mac3 <- as.raw(c(0x01, 0x02, 0x03, 0x05))
  mac_short <- as.raw(c(0x01, 0x02, 0x03))

  testthat::expect_true(hmac_check(mac1, mac2))
  testthat::expect_false(hmac_check(mac1, mac3))
  testthat::expect_false(hmac_check(mac1, mac_short))
})

testthat::test_that("decrypt_multi will use a list of keys to decrypt", {
  key <- generate_key()
  token <- encrypt(key, "hello")

  old_keys <- c(generate_key(), key, generate_key())
  
  Sys.sleep(4)

  testthat::expect_no_error(decrypt_multi(old_keys, token))
  testthat::expect_equal(decrypt_multi(old_keys, token), "hello")
  testthat::expect_error(decrypt_multi(old_keys, token, ttl = 2))
})
