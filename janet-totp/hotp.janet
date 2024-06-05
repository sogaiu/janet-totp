# RFC 4226 Section 5.3
#
# Step 1: Generate an HMAC-SHA-1 value Let HS = HMAC-SHA-1(K,C)  // HS
# is a 20-byte string
#
# Step 2: Generate a 4-byte string (Dynamic Truncation)
# Let Sbits = DT(HS)   //  DT, defined below,
#                      //  returns a 31-bit string
# Step 3: Compute an HOTP value
# Let Snum  = StToNum(Sbits)   // Convert S to a number in
#                                  0...2^{31}-1
# Return D = Snum mod 10^Digit //  D is a number in the range
#                                  0...10^{Digit}-1
#
# The Truncate function performs Step 2 and Step 3, i.e., the dynamic
# truncation and then the reduction modulo 10^Digit.  The purpose of
# the dynamic offset truncation technique is to extract a 4-byte
# dynamic binary code from a 160-bit (20-byte) HMAC-SHA-1 result.
#
#  DT(String) // String = String[0]...String[19]
#   Let OffsetBits be the low-order 4 bits of String[19]
#   Offset = StToNum(OffsetBits) // 0 <= OffSet <= 15
#   Let P = String[OffSet]...String[OffSet+3]
#  Return the Last 31 bits of P
#
# The reason for masking the most significant bit of P is to avoid
# confusion about signed vs. unsigned modulo computations.  Different
# processors perform these operations differently, and masking out the
# signed bit removes all ambiguity.
#
# Implementations MUST extract a 6-digit code at a minimum and possibly
# 7 and 8-digit code.  Depending on security requirements, Digit = 7 or
# more SHOULD be considered in order to extract a longer HOTP value.

########################################################################

(import ./hmac-sha-1 :as hmac)

########################################################################

(defn dyn-trunc
  [hash-string]
  (def expected-len 20)

  (assert (= expected-len (length hash-string))
          (string/format "Expected length %d, but got: %d"
                         expected-len (length hash-string)))
  # last four bits of last byte
  (def offset
    (band 2r00001111 (get hash-string (dec expected-len))))

  # XXX: consider using blshift below

  # interpret certain 4 bytes of hash-string as a number
  # but mask the sign bit
  (def p-masked
    # mask the sign bit (leftmost bit) in the leftmost byte
    (+ (* (math/pow 256 3) (band 2r01111111 (get hash-string offset)))
       (* (math/pow 256 2) (get hash-string (+ offset 1)))
       (* (math/pow 256 1) (get hash-string (+ offset 2)))
       (* (math/pow 256 0) (get hash-string (+ offset 3)))))

  # XXX: trying to use `band` after computing p may not work in janet
  #      because band has limits on the size of what it can handle,
  #      i.e.  2^31-1 is the max. thus, `band` is done above on the
  #      leftmost byte above during computation of p-masked.
  #(def p
  #  (+ (* (math/pow 256 3) (get hash-string offset)))
  #     (* (math/pow 256 2) (get hash-string (+ offset 1)))
  #     (* (math/pow 256 1) (get hash-string (+ offset 2)))
  #     (* (math/pow 256 0) (get hash-string (+ offset 3)))))
  #(def p-masked
  #  (band 2r01111111_11111111_11111111_11111111
  #        p))

  p-masked)

(comment

  (dyn-trunc (string (string/from-bytes 0 0 0 1) "000000"
                     "000000000"
                     (string/from-bytes 0)))
  # =>
  1

  (dyn-trunc (string (string/from-bytes 0 0 1 0) "000000"
                     "000000000"
                     (string/from-bytes 0)))
  # =>
  256

  (dyn-trunc (string (string/from-bytes 0 1 0 0) "000000"
                     "000000000"
                     (string/from-bytes 0)))
  # =>
  65536

  (dyn-trunc (string (string/from-bytes 0 1 1 1) "000000"
                     "000000000"
                     (string/from-bytes 0)))
  # =>
  65793

  (dyn-trunc (string (string/from-bytes 127 255 255 255) "000000"
                     "000000000"
                     (string/from-bytes 0)))
  # =>
  2147483647

  (dyn-trunc (string (string/from-bytes 255 255 255 255) "000000"
                     "000000000"
                     (string/from-bytes 0)))
  # =>
  2147483647

  (dyn-trunc (string (string/from-bytes 0 0 0 0 1) "00000"
                     "000000000"
                     (string/from-bytes 1)))
  # =>
  1

  (dyn-trunc (string (string/from-bytes 0 0 0 0 15) "00000"
                     "000000000"
                     (string/from-bytes 1)))
  # =>
  15

  )

# RFC 4226 Section 5.4
(comment

  (def hs
    (string "\x1f\x86\x98\x69\x0e\x02\xca\x16\x61\x85"
            "\x50\xef\x7f\x19\xda\x8e\x94\x5b\x55\x5a"))

  (def s-num (dyn-trunc hs))

  s-num
  # =>
  0x50ef7f19

  (def d
    (mod s-num (math/pow 10 6)))

  d
  # =>
  872921

  )

# XXX: only support sha-1 for now
# XXX: to use "large" values for counter, pass `(int/u64 "...")`
#      instead of an ordinary janet number -- not that this seems
#      likely needed in practice?
(defn hotp
  [key counter &opt params]
  (default params {})
  # https://en.wikipedia.org/wiki/HMAC-based_one-time_password#Algorithm
  #
  # A HOTP value length d (6–10, default is 6, and 6–8 is recommended)
  #
  # RFC 4226 Section 5.1
  #
  # Digit   number of digits in an HOTP value; system parameter
  (def {:digits digits} params)
  (default digits 6)

  # RFC 4226 Section 5.1
  #
  # C       8-byte counter value, the moving factor.  This counter
  #         MUST be synchronized between the HOTP generator (client)
  #         and the HOTP validator (server).
  (def counter-eight-bytes
    (int/to-bytes (int/u64 (string/format "%d" counter)) :be))

  (def hs
    (hmac/hmac-sha-1 (hmac/prepare-key key) counter-eight-bytes))

  (def s-num (dyn-trunc hs))

  (def d
    (mod s-num (math/pow 10 digits)))

  (def d-as-str
    (string/format (string "%0" digits "d") d))

  d-as-str)

# RFC 4226 Appendix D
(comment

  (def key "12345678901234567890")

  (hotp key 0)
  # =>
  "755224"

  (hotp key 1)
  # =>
  "287082"

  (hotp key 2)
  # =>
  "359152"

  (hotp key 3)
  # =>
  "969429"

  (hotp key 4)
  # =>
  "338314"

  (hotp key 5)
  # =>
  "254676"

  (hotp key 6)
  # =>
  "287922"

  (hotp key 7)
  # =>
  "162583"

  (hotp key 8)
  # =>
  "399871"

  (hotp key 9)
  # =>
  "520489"

  # XXX: not in official tests -- wanted leading zero
  (hotp key 30)
  # =>
  "026920"

  )

