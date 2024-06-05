# based on spork's base64.janet

(def base32/table
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

(defn array-pad-right
  [xs size padder]
  (let [l (length xs)]
    (if (< l size)
      (do (for i l size
            (put xs i padder))
        xs)
      xs)))

(comment

  (array-pad-right @[:a :b :c] 6 :x)
  # =>
  @[:a :b :c :x :x :x]

  (array-pad-right @[1 2 3] 6 0)
  # =>
  @[1 2 3 0 0 0]

  )

(defn array-pad-left
  [xs size padder]
  (let [l (length xs)]
    (if (< l size)
      (do (for i 0 (- size l)
            (array/insert xs i padder))
        xs)
      xs)))

(comment

  (array-pad-left @[:a :b :c] 6 :x)
  # =>
  @[:x :x :x :a :b :c]

  (array-pad-left @[1 2 3] 6 0)
  # =>
  @[0 0 0 1 2 3]

  )

(defn decimal->binary
  [x &opt bin]
  (default bin @[])
  (if (< x 1)
    (reverse bin)
    (let [rem (% x 2)
          new-x (math/floor (/ x 2))]
      (decimal->binary new-x (array/push bin rem)))))

(comment

  # XXX: seems odd this does not return @[0]
  (decimal->binary 0)
  # =>
  @[]

  (decimal->binary 1)
  # =>
  @[1]

  (decimal->binary 2)
  # =>
  @[1 0]

  (decimal->binary 7)
  # =>
  @[1 1 1]

  )

(defn binary->decimal
  [xs]
  (var num 0)
  (for i 0 (length xs)
    (if (= 1 (get (reverse xs) i))
      (set num (+ num (math/pow 2 i)))))
  num)

(comment

  (binary->decimal @[])
  # =>
  0

  (binary->decimal @[0])
  # =>
  0

  (binary->decimal @[1 1 1])
  # =>
  7

  )

(defn octets->quintets
  [octets]
  (->> octets
       flatten
       (partition 5)
       (map |(array ;$0))))

(comment

  # extracted from encode function below
  (defn make-octets
    [str]
    (map |(-> $0
              decimal->binary
              (array-pad-left 8 0))
         (string/bytes str)))

  (make-octets "hi")
  # =>
  @[@[0 1 1 0 1 0 0 0]
    @[0 1 1 0 1 0 0 1]]

  (octets->quintets @[@[0 1 1 0 1 0 0 0]
                      @[0 1 1 0 1 0 0 1]])
  # =>
  @[@[0 1 1 0 1]
    @[0 0 0 0 1]
    @[1 0 1 0 0]
    @[1]]

  )

(defn quintets->octets
  [quintets]
  (->> quintets
       flatten
       (partition 8)))

(comment

  (quintets->octets @[@[0 1 1 0 1]
                      @[0 0 0 0 1]
                      @[1 0 1 0 0]
                      @[1]])
  # =>
  @[[0 1 1 0 1 0 0 0]
    [0 1 1 0 1 0 0 1]]

  )

(defn octuples->bytes [xs]
  (let [quintets
        (map (fn [x]
               (-> (string/find (string/from-bytes x) base32/table)
                   (decimal->binary)
                   (array-pad-left 5 0))) xs)
        octets (quintets->octets quintets)]
    (apply string/from-bytes (map binary->decimal octets))))

(comment

  (octuples->bytes "MZXW6YTB")
  # =>
  "fooba"

  )

(defn pad-last-quintet [xs]
  (let [last-index (dec (length xs))]
    (update xs last-index array-pad-right 5 0)))

(comment

  (pad-last-quintet @[@[0 1 1 0 1]
                      @[0 0 0 0 1]
                      @[1 0 1 0 0]
                      @[1]])
  # =>
  @[@[0 1 1 0 1]
    @[0 0 0 0 1]
    @[1 0 1 0 0]
    @[1 0 0 0 0]]

  )

(defn add-padding [s]
  (if (zero? (% (length s) 8))
    s
    (let [pad-count (- 8 (% (length s) 8))]
      (string s (string/repeat "=" pad-count)))))

(comment

  (add-padding "")
  # =>
  ""

  (add-padding "1")
  # =>
  "1======="

  (add-padding "12")
  # =>
  "12======"

  (add-padding "123")
  # =>
  "123====="

  (add-padding "1238790")
  # =>
  "1238790="

  (add-padding "12387900")
  # =>
  "12387900"

  )

(defn encode
  "Converts a string of any format (UTF-8, binary, ..) to base32 encoding."
  [s]
  (if (> (length s) 0)
    (let [octets (map |(-> $0
                           decimal->binary
                           (array-pad-left 8 0))
                      (string/bytes s))
          sextets (pad-last-quintet (octets->quintets octets))
          bytes (map binary->decimal sextets)
          base32-bytes (map (fn [i] (get base32/table i)) bytes)
          base32 (add-padding (apply string/from-bytes base32-bytes))]
      base32)
    ""))

(comment

  (encode "")
  # =>
  ""

  (encode "f")
  # =>
  "MY======"

  (encode "fo")
  # =>
  "MZXQ===="

  (encode "foo")
  # =>
  "MZXW6==="

  (encode "foob")
  # =>
  "MZXW6YQ="

  (encode "fooba")
  # =>
  "MZXW6YTB"

  (encode "foobar")
  # =>
  "MZXW6YTBOI======"

  )

(defn decode
  ```
  Converts a base32 encoded string to its binary representation of any format
  (UTF-8, binary, ..).
  ```
  [s]
  (if-not (empty? s)
    (let [without-padding (string/replace-all "=" "" s)
          padded? (not (zero? (% (length without-padding) 8)))
          octuples (partition 8 without-padding)
          bytes (map octuples->bytes octuples)
          base32 (apply string bytes)]
      (if padded? (slice base32 0 (dec (length base32))) base32))
    ""))

(comment

  (decode "MZXW6YTBOI======")
  # =>
  "foobar"

  (decode "MZXW6YTB")
  # =>
  "fooba"

  (decode "MZXW6YQ=")
  # =>
  "foob"

  (decode "MZXW6===")
  # =>
  "foo"

  (decode "MZXQ====")
  # =>
  "fo"

  (decode "MY======")
  # =>
  "f"

  (decode "")
  # =>
  ""

  )
