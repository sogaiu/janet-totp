# from RFC 2104

# 2. Definition of HMAC
#
#    The definition of HMAC requires a cryptographic hash function, which
#    we denote by H, and a secret key K. We assume H to be a cryptographic
#    hash function where data is hashed by iterating a basic compression
#    function on blocks of data.   We denote by B the byte-length of such
#    blocks (B=64 for all the above mentioned examples of hash functions),
#    and by L the byte-length of hash outputs (L=16 for MD5, L=20 for
#    SHA-1).  The authentication key K can be of any length up to B, the
#    block length of the hash function.  Applications that use keys longer
#    than B bytes will first hash the key using H and then use the
#    resultant L byte string as the actual key to HMAC. In any case the
#    minimal recommended length for K is L bytes (as the hash output
#    length). See section 3 for more information on keys.
#
#    We define two fixed and different strings ipad and opad as follows
#    (the 'i' and 'o' are mnemonics for inner and outer):
#
#                    ipad = the byte 0x36 repeated B times
#                   opad = the byte 0x5C repeated B times.
#
#    To compute HMAC over the data `text' we perform
#
#                     H(K XOR opad, H(K XOR ipad, text))
#
#    Namely,
#
#     (1) append zeros to the end of K to create a B byte string
#         (e.g., if K is of length 20 bytes and B=64, then K will be
#          appended with 44 zero bytes 0x00)
#     (2) XOR (bitwise exclusive-OR) the B byte string computed in step
#         (1) with ipad
#     (3) append the stream of data 'text' to the B byte string resulting
#         from step (2)
#     (4) apply H to the stream generated in step (3)
#     (5) XOR (bitwise exclusive-OR) the B byte string computed in
#         step (1) with opad
#     (6) append the H result from step (4) to the B byte string
#         resulting from step (5)
#     (7) apply H to the stream generated in step (6) and output
#         the result

########################################################################

# we'll be doing hmac-sha1, so:
#
# H = sha-1
# B = 64 (bytes)
# L = 20 (bytes)

########################################################################

(import ./sha-1 :as s)

########################################################################

# for sha-1
(def block-len 64)

(defn buffer-pad-right
  [buf size padder]
  (let [l (length buf)]
    (if (< l size)
      (do
        (for i l size
          (buffer/push-byte buf padder))
        buf)
      buf)))

(comment

  (buffer-pad-right @"123" 6 0)
  # =>
  @"123\0\0\0"

  )

# https://en.wikipedia.org/wiki/HMAC#Definition
#
# K' is a block-sized key derived from the secret key, K; either by
# padding to the right with 0s up to the block size, or by hashing
# down to less than or equal to the block size first and then padding
# to the right with zeros.
#
# RFC 2104 Section 2
#
# The authentication key K can be of any length up to B, the block
# length of the hash function.  Applications that use keys longer than
# B bytes will first hash the key using H and then use the
# resultant L byte string as the actual key to HMAC.
#
# ...
#
# (1) append zeros to the end of K to create a B byte string
#     (e.g., if K is of length 20 bytes and B=64, then K will be
#     appended with 44 zero bytes 0x00)
(defn prepare-key
  [key]
  (def key-len (length key))
  (cond
    (> key-len block-len)
    (-> (s/sha-1-bytes key)
        (buffer-pad-right block-len 0))
    #
    (< key-len block-len)
    (buffer-pad-right (buffer key) block-len 0)
    #
    (buffer key)))

(comment

  (prepare-key (string "0123456789" "0123456789" "0123456789"
                       "0123456789" "0123456789" "0123456789"))
  # =>
  @"012345678901234567890123456789012345678901234567890123456789\0\0\0\0"

  (prepare-key (string "0123456789" "0123456789" "0123456789"
                       "0123456789" "0123456789" "0123456789"
                       "0123456789"))
  # =>
  (buffer "\x19E\"\xB2\xBD\xB1\xF1\x83\x8A--$\xA2H  \x01\xACh8"
          "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
          "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")

  (prepare-key (string "0123456789" "0123456789" "0123456789"
                       "0123456789" "0123456789" "0123456789"
                       "0123"))
  # =>
  @"0123456789012345678901234567890123456789012345678901234567890123"

  (prepare-key (string "1234567890" "1234567890"))
  # =>
  (buffer "12345678901234567890"
          "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
          "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")

  )

(defn buffer-xor
  [left right]
  (def m (map bxor
              (string/bytes left)
              (string/bytes right)))
  #(printf "m: %n" m)
  #(print "length m: " (length m))
  (def r (buffer/from-bytes ;m))
  #(print "length r: " (length r))
  r)

(comment

  (buffer-xor "000000" "111111")
  # =>
  @"\x01\x01\x01\x01\x01\x01"

  (buffer-xor "000000" "222222")
  # =>
  @"\x02\x02\x02\x02\x02\x02"

  (buffer-xor "222222" "222222")
  # =>
  @"\0\0\0\0\0\0"

  (buffer-xor "000000" "123456")
  # =>
  @"\x01\x02\x03\x04\x05\x06"

  (buffer-xor "222222" "111111")
  # =>
  @"\x03\x03\x03\x03\x03\x03"

  )

(def ipad
  (buffer-pad-right @"" block-len (chr "\x36")))

# RFC 2104 Section 2
#
#  (2) XOR (bitwise exclusive-OR) the B byte string computed in step
#      (1) with ipad
#
# N.B. B = 64 for sha-1
(defn inner-pad
  [key]
  (buffer-xor key ipad))

(comment

  (inner-pad (prepare-key "123"))
  # =>
  (buffer "\a\x04\x05"
          "6666666666666666666666666666666666666666666666666666666666666")

  (inner-pad (prepare-key (buffer "0123456789" "0123456789" "0123456789"
                                  "0123456789" "0123456789" "0123456789"
                                  "0123456789")))
  # =>
  (buffer "/s\x14\x84\x8B\x87\xC7\xB5\xBC\e\e\x12\x94~\x16\x167\x9A^\x0E"
          "66666666666666666666666666666666666666666666")

  )

(def opad
  (buffer-pad-right @"" block-len (chr "\x5c")))

# RFC 2104 Section 2
#
# (5) XOR (bitwise exclusive-OR) the B byte string computed in
#     step (1) with opad
#
# N.B. B = 64 for sha-1
(defn outer-pad
  [key]
  (buffer-xor key opad))

(comment

  (outer-pad (prepare-key "123"))
  # =>
  (buffer "mno"
          "\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"
          "\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"
          "\\\\\\")

  (outer-pad (prepare-key (buffer "0123456789" "0123456789" "0123456789"
                                  "0123456789" "0123456789" "0123456789"
                                  "0123456789")))
  # =>
  (buffer "E\x19~\xEE\xE1\xED\xAD\xDF\xD6qqx\xFE\x14||]\xF04d"
          "\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"
          "\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\")

  )

(defn hmac-sha-1
  [key message]
  (def keyp (prepare-key key))

  (def inner-h
    (s/sha-1-bytes (buffer (inner-pad keyp) message)))

  (def outer-h
    (s/sha-1-bytes (buffer (outer-pad keyp) inner-h)))

  outer-h)

# RFC 2202 Section 3
(comment

  # 1
  (hmac-sha-1
    (prepare-key (string "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                         "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"))
    "Hi There")
  # =>
  @"\xB6\x171\x86U\x05rd\xE2\x8B\xC0\xB6\xFB7\x8C\x8E\xF1F\xBE\0"

  # 2
  (hmac-sha-1 (prepare-key "Jefe") "what do ya want for nothing?")
  # =>
  @"\xEF\xFC\xDFj\xE5\xEB/\xA2\xD2t\x16\xD5\xF1\x84\xDF\x9C%\x9A|y"

  # 3
  (hmac-sha-1
    (prepare-key (string "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                         "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"))
    (string "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
            "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
            "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
            "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
            "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"))
  # =>
  @"\x12]sB\xB9\xAC\x11\xCD\x91\xA3\x9A\xF4\x8A\xA1{Oc\xF1u\xD3"

  # 4
  (hmac-sha-1
    (prepare-key (string "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
                         "\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14"
                         "\x15\x16\x17\x18\x19"))
    (string "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
            "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
            "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
            "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
            "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"))
  # =>
  @"L\x90\a\xF4\x02bP\xC6\xBC\x84\x14\xF9\xBFP\xC8l-r5\xDA"

  # 5
  (hmac-sha-1
    (prepare-key (string "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
                         "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"))
    "Test With Truncation")
  # =>
  @"L\x1A\x03BKU\xE0\x7F\xE7\xF2{\xE1\xD5\x8B\xB92J\x9AZ\x04"

  # 6
  (hmac-sha-1
    (prepare-key (string "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                         "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                         "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                         "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                         "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                         "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                         "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                         "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"))
    "Test Using Larger Than Block-Size Key - Hash Key First")
  # =>
  @"\xAAJ\xE5\xE1Rr\xD0\x0E\x95pV7\xCE\x8A;U\xED@!\x12"

  # 7 - N.B. original RFC text was missing the space after 2nd "Larger"
  (hmac-sha-1
    (prepare-key (string "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                         "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                         "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                         "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                         "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                         "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                         "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                         "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"))
    (string "Test Using Larger Than Block-Size Key and Larger "
            "Than One Block-Size Data"))
  # =>
  @"\xE8\xE9\x9D\x0FE#}xmk\xBA\xA7\x96\\x\b\xBB\xFF\x1A\x91"

  )

