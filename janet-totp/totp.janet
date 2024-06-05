# RFC 6238 Section 4
#
# This variant of the HOTP algorithm specifies the calculation of a
# one-time password value, based on a representation of the counter as
# a time factor.

# RFC 6238 Section 4.2
#
# Basically, we define TOTP as TOTP = HOTP(K, T), where T is an integer
# and represents the number of time steps between the initial counter
# time T0 and the current Unix time.
#
# More specifically, T = (Current Unix time - T0) / X, where the
# default floor function is used in the computation.
#
# For example, with T0 = 0 and Time Step X = 30, T = 1 if the current
# Unix time is 59 seconds, and T = 2 if the current Unix time is
# 60 seconds.

# RFC 6238 Section 4.1
#
# o  X represents the time step in seconds (default value X =
#    30 seconds) and is a system parameter.
#
# o  T0 is the Unix time to start counting time steps (default value is
#    0, i.e., the Unix epoch) and is also a system parameter.

########################################################################

(import ./hotp :as h)

########################################################################

# "time factor" aka T in rfc 6238
(defn calc-time-factor
  [&opt params]
  (default params {})
  (def {:now now
        :start-time start-time
        :time-step time-step}
    params)
  (default now (os/time))
  (default start-time 0)
  (default time-step 30)

  (def time-factor
    (math/floor (/ (- now start-time) time-step)))
  #
  time-factor)

(comment

  (calc-time-factor {:now 0})
  # =>
  0

  (calc-time-factor {:now 59})
  # =>
  1

  (calc-time-factor {:now 61})
  # =>
  2

  (calc-time-factor {:now 59 :time-step 60})
  # =>
  0
  
  )

(defn totp
  [key &opt time-factor params]
  (default time-factor (calc-time-factor))
  (default params {})
  (h/hotp key time-factor params))

# RFC 6238 Appendix B
(comment

  (def key "12345678901234567890")

  (totp key 
        (calc-time-factor {:now 59})
        {:digits 8})
  # =>
  "94287082"

  (totp key 
        (calc-time-factor {:now 1111111109})
        {:digits 8})
  # =>
  "07081804"

  (totp key 
        (calc-time-factor {:now 1111111111})
        {:digits 8})
  # =>
  "14050471"

  (totp key 
        (calc-time-factor {:now 1234567890})
        {:digits 8})
  # =>
  "89005924"

  (totp key 
        (calc-time-factor {:now 2000000000})
        {:digits 8})
  # =>
  "69279037"

  (totp key 
        (calc-time-factor {:now 20000000000})
        {:digits 8})
  # =>
  "65353130"

  )
