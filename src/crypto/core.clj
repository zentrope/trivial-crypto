(ns crypto.core
  (:import
    javax.crypto.spec.SecretKeySpec
    javax.crypto.SecretKeyFactory
    javax.crypto.Cipher
    javax.crypto.spec.PBEKeySpec
    javax.crypto.spec.DESKeySpec
    javax.crypto.spec.IvParameterSpec))

;;-----------------------------------------------------------------------------

(def ^:private salt
  (byte-array [1 2 3 4 5 6 7 8]))

(def ^:private iterations
  65536)

(def ^:private key-len
  256)

(defn bytes->hex
  [bytes]
  (->> bytes (map (partial format "%02x")) (apply str)))

(defn hex->bytes
  [s]
  (letfn [(->byte [c1 c2]
            (unchecked-byte
             (+ (bit-shift-left (Character/digit c1 16) 4)
                (Character/digit c2 16))))]
    (-> (mapv #(apply ->byte %) (partition 2 s))
        (byte-array))))

(defn- iv-params
  [encryptor]
  (-> (.getParameters encryptor)
      (.getParameterSpec IvParameterSpec)
      (.getIV)
      (IvParameterSpec.)))

(defn- des-cipher
  [passphrase]
  (let [factory (SecretKeyFactory/getInstance "DES")
        spec (DESKeySpec. passphrase)
        tmp (.generateSecret factory spec)
        secret (SecretKeySpec. (.getEncoded tmp) "DES")
        encipher (doto (Cipher/getInstance "DES/ECB/PKCS5Padding")
                    (.init Cipher/ENCRYPT_MODE secret))
        decipher (doto (Cipher/getInstance "DES/ECB/PKCS5Padding")
                   (.init Cipher/DECRYPT_MODE secret))]
    [encipher decipher]))

(defn- aes-cipher
  [passphrase]
  (let [factory (SecretKeyFactory/getInstance "PBKDF2WithHmacSHA1")
        spec (PBEKeySpec. (.toCharArray (String. passphrase))
                          salt iterations key-len)
        tmp (.generateSecret factory spec)
        secret (SecretKeySpec. (.getEncoded tmp) "AES")
        encipher (doto (Cipher/getInstance "AES/CBC/PKCS5Padding")
                    (.init Cipher/ENCRYPT_MODE secret))
        decipher (doto (Cipher/getInstance "AES/CBC/PKCS5Padding")
                   (.init Cipher/DECRYPT_MODE secret (iv-params encipher)))]
    [encipher decipher]))

;;-----------------------------------------------------------------------------

(defn- cipher
  [type passphrase]
  (case type
    :aes (aes-cipher passphrase)
    :des (des-cipher passphrase)
    (throw (ex-info (format "Bad type: [%s], try [:aes :des]." type) {}))))

;;-----------------------------------------------------------------------------

(defn encrypt
  [{:keys [encryptor]} string]
  (bytes->hex (.doFinal encryptor (.getBytes string "UTF-8"))))

(defn decrypt
  [{:keys [decryptor]} data]
  (String. (.doFinal decryptor (hex->bytes data))))

(defn make-crypto
  [type passphrase & [{:keys [hex?] :as opts :or [{hex? false}]}]]
  (try
    (let [secret (if hex? (hex->bytes passphrase) (.getBytes passphrase))
          [en de] (cipher type secret)]
      {:type type :encryptor en :decryptor de})
    (catch java.security.InvalidKeyException e
      (throw (ex-info "Can't make key. Are the US JCE jars installed?"
                      {:jvm (System/getProperty "java.home")} e)))))
